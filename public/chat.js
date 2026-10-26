(() => {
  const crypto = window.ClipVaultChatCrypto;
  const $ = (id) => document.getElementById(id);
  let vaultCode = "";
  let identity = null;
  let privateKeys = null;
  let ownFingerprint = "";
  let conversations = [];
  let sentRequests = [];
  let activeConversation = null;
  let activeMessageKey = null;
  let messageCursor = "0";
  let pollTimer = 0;
  let messagePollTimer = 0;
  let polling = false;
  let messageLoading = false;
  let statusTimer = 0;
  let joiningChat = false;
  let sendingMessage = false;
  let typingHeartbeat = 0;
  let typingPollTimer = 0;
  let lastTypingSentAt = 0;
  let renderedMessageIds = new Set();
  let pendingMessagesByCiphertext = new Map();
  let qrCameraStream = null;
  let qrCameraFrame = 0;
  let knownIncomingRequestIds = null;

  function setStatus(message, isError = false) {
    window.clearTimeout(statusTimer);
    $("chatStatus").textContent = message;
    $("chatStatus").classList.toggle("error", isError);
    if (message && !isError) {
      statusTimer = window.setTimeout(() => {
        if ($("chatStatus").textContent === message) setStatus("");
      }, 2400);
    }
  }

  function showSection(sectionId) {
    for (const id of ["chatSetup", "chatUnlock", "chatWorkspace"]) {
      $(id).classList.toggle("hidden", id !== sectionId);
    }
  }

  function endpoint(path) {
    return `/api/vaults/${encodeURIComponent(vaultCode)}${path}`;
  }

  async function api(method, path, body) {
    const response = await fetch(endpoint(path), {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "Chat request failed");
    return result;
  }

  function clearChatLists() {
    $("chatRequests").replaceChildren();
    $("chatConversations").replaceChildren();
    $("chatColumns").classList.add("no-active-chat");
    $("chatColumns").classList.remove("has-active-chat");
  }

  async function loadIdentity() {
    identity = await api("GET", "/chat/identity");
    if (!identity.registered) {
      $("chatSetupMessage").textContent = "Preparing encrypted chat for this vault…";
      $("chatSetup").querySelector("h3").textContent = "Private chat";
      showSection("chatSetup");
      await beginIdentitySetup();
      return;
    }
    if (identity.wrappedPrivateKey.startsWith("cv2.")) {
      await unlockIdentity(vaultCode);
      return;
    }
    $("chatUnlock").querySelector("h3").textContent = "Update chat security";
    $("chatUnlock").querySelector("p").textContent = "Enter your recovery phrase once to switch this chat to vault-code access.";
    $("chatRecoveryInput").placeholder = "Existing recovery phrase";
    $("chatUnlockButton").textContent = "Update chat";
    showSection("chatUnlock");
  }

  async function unlockIdentity(recoveryPhrase) {
    privateKeys = await crypto.unlockPrivateKey(identity, recoveryPhrase);
    ownFingerprint = await crypto.fingerprint(identity.publicKey);
    $("chatOwnFingerprint").textContent = ownFingerprint;
    $("chatRecoveryInput").value = "";
    showSection("chatWorkspace");
    setStatus("");
    await refreshChatData();
  }

  async function beginIdentitySetup() {
    $("chatCreateIdentity").disabled = true;
    setStatus("");
    try {
      const created = await crypto.createIdentity(vaultCode);
      const { publicKey, wrappedPrivateKey, recoverySalt, recoveryIv } = created;
      const savedIdentity = await api("POST", "/chat/identity", { publicKey, wrappedPrivateKey, recoverySalt, recoveryIv });
      identity = { registered: true, peerId: savedIdentity.peerId, publicKey, wrappedPrivateKey, recoverySalt, recoveryIv };
      await unlockIdentity(vaultCode);
    } catch (error) {
      if (error.message.includes("already exists")) {
        await loadIdentity();
        return;
      }
      setStatus(error.message, true);
    } finally {
      $("chatCreateIdentity").disabled = false;
    }
  }

  async function migrateLegacyIdentity() {
    $("chatUnlockButton").disabled = true;
    try {
      const migrated = await crypto.migrateIdentityToCode(identity, $("chatRecoveryInput").value, vaultCode);
      await api("PUT", "/chat/identity", { publicKey: identity.publicKey, ...migrated });
      identity = { ...identity, ...migrated };
      $("chatRecoveryInput").value = "";
      await unlockIdentity(vaultCode);
    } catch (error) {
      setStatus("Could not update this chat. Check the recovery phrase and try again.", true);
    } finally {
      $("chatUnlockButton").disabled = false;
    }
  }

  function appendMessage(message, plaintext) {
    const element = document.createElement("div");
    element.className = `chat-message${message.senderId === identity.peerId ? " mine" : ""}`;
    if (message.id) {
      element.dataset.messageId = String(message.id);
      renderedMessageIds.add(String(message.id));
    }
    const content = document.createElement("span");
    content.textContent = plaintext;
    const time = document.createElement("time");
    if (message.pending) {
      time.textContent = "Sending…";
      element.classList.add("pending");
    } else {
      setMessageTime(time, message.createdAt);
    }
    element.append(content, time);
    $("chatMessages").append(element);
    return element;
  }

  function setMessageTime(time, createdAt) {
    time.dateTime = new Date(createdAt).toISOString();
    time.textContent = new Date(createdAt).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
    time.title = new Date(createdAt).toLocaleString();
  }

  function reconcilePendingMessage(element, message) {
    if (!element) return;
    renderedMessageIds.delete(element.dataset.messageId || "");
    element.dataset.messageId = String(message.id);
    renderedMessageIds.add(String(message.id));
    element.classList.remove("pending");
    setMessageTime(element.querySelector("time"), message.createdAt);
  }

  async function loadMessages() {
    if (messageLoading || !activeConversation || !activeMessageKey) return;
    messageLoading = true;
    const conversation = activeConversation;
    const messageKey = activeMessageKey;
    try {
      const result = await api(
        "GET",
        `/chat/conversations/${encodeURIComponent(conversation.id)}/messages?after=${encodeURIComponent(messageCursor)}`,
      );
      if (activeConversation?.id !== conversation.id) return;
      const unread = [];
      for (const message of result.messages) {
        messageCursor = message.id;
        const pending = pendingMessagesByCiphertext.get(message.ciphertext);
        if (pending) {
          reconcilePendingMessage(pending, message);
          pendingMessagesByCiphertext.delete(message.ciphertext);
        } else if (!renderedMessageIds.has(String(message.id))) unread.push(message);
      }
      const plaintexts = await Promise.all(unread.map(async (message) => {
        try {
          return await crypto.decryptMessage(
            messageKey,
            message,
            conversation.id,
            message.senderId === identity.peerId
              ? identity.publicKey.signing
              : conversation.peerPublicKey.signing,
          );
        } catch {
          return "Could not decrypt this message. Check the safety code with your contact.";
        }
      }));
      if (activeConversation?.id !== conversation.id) return;
      unread.forEach((message, index) => appendMessage(message, plaintexts[index]));
      if (result.messages.length) {
        const messageList = $("chatMessages");
        messageList.scrollTo({
          top: messageList.scrollHeight,
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        });
      }
    } finally {
      messageLoading = false;
    }
  }

  async function updateTypingStatus(isTyping) {
    if (!activeConversation || !vaultCode) return;
    try {
      await api("POST", `/chat/conversations/${encodeURIComponent(activeConversation.id)}/typing`, { typing: isTyping });
    } catch { /* Typing status is best-effort and must not interrupt chat. */ }
  }

  async function refreshTypingStatus() {
    if (!activeConversation || $("chatPanel").classList.contains("hidden")) return;
    try {
      const result = await api("GET", `/chat/conversations/${encodeURIComponent(activeConversation.id)}/typing`);
      const indicator = $("chatTypingIndicator");
      indicator.classList.toggle("hidden", !result.typing);
      indicator.setAttribute("aria-hidden", String(!result.typing));
    } catch {
      $("chatTypingIndicator").classList.add("hidden");
    }
  }

  function stopTyping() {
    window.clearInterval(typingHeartbeat);
    typingHeartbeat = 0;
    if (lastTypingSentAt) void updateTypingStatus(false);
    lastTypingSentAt = 0;
  }

  function startTyping() {
    if (!activeConversation || !$("chatMessageInput").value.trim()) return;
    if (!typingHeartbeat) {
      void updateTypingStatus(true);
      lastTypingSentAt = Date.now();
      typingHeartbeat = window.setInterval(() => {
        if (!$("chatMessageInput").value.trim()) return stopTyping();
        if (Date.now() - lastTypingSentAt >= 4000) {
          void updateTypingStatus(true);
          lastTypingSentAt = Date.now();
        }
      }, 1000);
    }
  }

  async function selectConversation(conversation) {
    stopTyping();
    try {
      const peerFingerprint = await crypto.fingerprint(conversation.peerPublicKey);
      const pinKey = `clipvault-chat-peer:${vaultCode}:${conversation.peerId}`;
      let pinnedFingerprint = null;
      try { pinnedFingerprint = localStorage.getItem(pinKey); } catch {}
      if (pinnedFingerprint && pinnedFingerprint !== peerFingerprint) {
        activeConversation = null;
        activeMessageKey = null;
        $("chatThreadEmpty").textContent = "This contact’s encryption key changed. Do not send messages until you verify the safety code.";
        $("chatThreadEmpty").classList.remove("hidden");
        $("chatActiveThread").classList.add("hidden");
        $("chatColumns").classList.add("no-active-chat");
        $("chatColumns").classList.remove("has-active-chat");
        setStatus("Warning: the saved safety code for this contact changed.", true);
        return;
      }
      if (!pinnedFingerprint) {
        try { localStorage.setItem(pinKey, peerFingerprint); } catch {}
      }
      activeConversation = conversation;
      activeMessageKey = await crypto.deriveConversationKey(
        privateKeys.agreement,
        conversation.peerPublicKey.agreement,
        identity.peerId,
        conversation.peerId,
      );
      messageCursor = "0";
      $("chatPeerCode").textContent = contactLabel(conversation.peerId);
      $("chatPeerFingerprint").textContent = peerFingerprint;
      $("chatMessages").replaceChildren();
      renderedMessageIds = new Set();
      pendingMessagesByCiphertext.clear();
      $("chatThreadEmpty").classList.add("hidden");
      $("chatActiveThread").classList.remove("hidden");
      $("chatColumns").classList.remove("no-active-chat");
      $("chatColumns").classList.add("has-active-chat");
      setStatus("");
      await loadMessages();
      void refreshTypingStatus();
      if (!typingPollTimer) typingPollTimer = window.setInterval(() => void refreshTypingStatus(), 2000);
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  function renderHeaderRequests(requests) {
    const container = $("chatNotificationList");
    const count = $("chatNotificationCount");
    container.replaceChildren();
    count.textContent = requests.length > 99 ? "99+" : String(requests.length);
    count.classList.toggle("hidden", requests.length === 0);
    if (!requests.length) {
      const empty = document.createElement("p");
      empty.className = "chat-notification-empty";
      empty.textContent = "No new chat requests.";
      container.append(empty);
      return;
    }
    for (const request of requests) {
      const item = document.createElement("div");
      item.className = "chat-notification-item";
      const label = document.createElement("span");
      label.textContent = `Request from ${contactLabel(request.peerId)}`;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "Review";
      button.onclick = () => {
        $("chatNotificationPanel").classList.add("hidden");
        $("chatNotificationButton").setAttribute("aria-expanded", "false");
        $("chatTab").click();
      };
      item.append(label, button);
      container.append(item);
    }
  }

  async function loadRequests() {
    const result = await api("GET", "/chat/requests");
    const requests = result.requests || [];
    const currentIds = new Set(requests.map((request) => request.id));
    const newIncomingIds = new Set();
    if (knownIncomingRequestIds !== null) {
      for (const request of requests) {
        if (!knownIncomingRequestIds.has(request.id)) {
          newIncomingIds.add(request.id);
          if (typeof window.toast === "function") window.toast(`New chat request from ${contactLabel(request.peerId)}`);
        }
      }
    }
    knownIncomingRequestIds = currentIds;
    renderHeaderRequests(requests);
    const container = $("chatRequests");
    container.replaceChildren();
    if (!requests.length) {
      $("chatRequestsSection").classList.add("hidden");
    } else {
      $("chatRequestsSection").classList.remove("hidden");
    }
    for (const request of requests) {
      const item = document.createElement("div");
      item.className = `chat-incoming-card${newIncomingIds.has(request.id) ? " is-new" : ""}`;
      const copy = document.createElement("div");
      copy.className = "chat-request-copy";
      const code = document.createElement("strong");
      code.textContent = contactLabel(request.peerId);
      const detail = document.createElement("small");
      detail.textContent = "Wants to start a chat";
      copy.append(code, detail);
      const actions = document.createElement("div");
      actions.className = "chat-request-actions";
      for (const [action, title] of [["accept", "Accept"], ["reject", "Decline"]]) {
        const button = document.createElement("button");
        button.className = action === "accept" ? "chat-request-accept" : "chat-request-decline";
        button.type = "button";
        button.textContent = title;
        button.onclick = async () => {
          const actionButtons = [...actions.querySelectorAll("button")];
          actionButtons.forEach((item) => { item.disabled = true; });
          button.textContent = action === "accept" ? "Accepting…" : "Declining…";
          try {
            const accepted = action === "accept";
            const response = await api(
              "POST",
              `/chat/requests/${encodeURIComponent(request.id)}/${action}`,
              {},
            );
            await refreshChatData();
            if (accepted) {
              const conversation = conversations.find((item) => item.id === response.id);
              if (conversation) await selectConversation(conversation);
            }
          } catch (error) {
            setStatus(error.message, true);
          } finally {
            actionButtons.forEach((item) => { item.disabled = false; });
            button.textContent = title;
          }
        };
        actions.append(button);
      }
      item.append(copy, actions);
      container.append(item);
    }

    sentRequests = result.sentRequests || [];
  }

  async function loadConversations() {
    const result = await api("GET", "/chat/conversations");
    conversations = result.conversations;
    const container = $("chatConversations");
    container.replaceChildren();
    const conversationsByPeer = new Map(conversations.map((conversation) => [conversation.peerId, conversation]));
    const statusLabels = { pending: "Waiting", accepted: "Accepted", rejected: "Declined" };
    const items = [
      ...conversations.map((conversation) => ({
        peerId: conversation.peerId,
        conversation,
        request: sentRequests.find((item) => item.peerId === conversation.peerId),
        createdAt: conversation.createdAt,
      })),
      ...sentRequests
        .filter((request) => !conversationsByPeer.has(request.peerId))
        .map((request) => ({ peerId: request.peerId, request, createdAt: request.createdAt })),
    ].sort((a, b) => b.createdAt - a.createdAt);
    $("chatConversationsSection").classList.toggle("hidden", items.length === 0);
    for (const item of items) {
      const row = item.conversation ? document.createElement("button") : document.createElement("div");
      row.className = item.conversation ? "chat-list-item" : "chat-list-item chat-outgoing-request";
      if (item.conversation) {
        row.type = "button";
        if (activeConversation?.id === item.conversation.id) row.setAttribute("aria-current", "page");
        row.onclick = async () => {
          await selectConversation(item.conversation);
          for (const listItem of container.querySelectorAll(".chat-list-item")) listItem.removeAttribute("aria-current");
          if (activeConversation?.id === item.conversation.id) row.setAttribute("aria-current", "page");
        };
      }
      const peer = document.createElement("span");
      peer.className = "chat-conversation-code";
      peer.textContent = contactLabel(item.peerId);
      row.append(peer);
      const status = item.request?.status || (item.conversation ? "accepted" : "pending");
      const badge = document.createElement("small");
      badge.className = "chat-request-status";
      badge.dataset.status = status;
      badge.textContent = statusLabels[status] || "Connected";
      row.append(badge);
      container.append(row);
    }
    if (activeConversation) {
      const updated = conversations.find((item) => item.id === activeConversation.id);
      if (updated) {
        const pinKey = `clipvault-chat-peer:${vaultCode}:${updated.peerId}`;
        let pinnedFingerprint = null;
        try { pinnedFingerprint = localStorage.getItem(pinKey); } catch {}
        if (pinnedFingerprint && pinnedFingerprint !== await crypto.fingerprint(updated.peerPublicKey)) {
          activeConversation = null;
          activeMessageKey = null;
          $("chatThreadEmpty").textContent = "This contact’s encryption key changed. Do not send messages until you verify the safety code.";
          $("chatThreadEmpty").classList.remove("hidden");
          $("chatActiveThread").classList.add("hidden");
          $("chatColumns").classList.add("no-active-chat");
          $("chatColumns").classList.remove("has-active-chat");
          setStatus("Warning: the saved safety code for this contact changed.", true);
        } else {
          activeConversation = updated;
        }
      }
    }
  }

  async function refreshChatData(includeMessages = true) {
    if (!privateKeys) return;
    await loadRequests();
    await loadConversations();
    if (includeMessages && !$("chatPanel").classList.contains("hidden")) await loadMessages();
  }

  function contactLabel(peerId) {
    return peerId ? "Contact · " + peerId.slice(0, 6).toUpperCase() : "New contact";
  }

  function setInviteToken(token) {
    $("chatInviteToken").value = token;
    $("chatSendRequest").disabled = !token;
    $("chatStartForm").classList.toggle("hidden", !token);
    if (token) {
      $("chatStartStatus").textContent = "QR scanned. Send a request to continue.";
      $("chatStartStatus").classList.remove("error");
    }
  }

  function inviteTokenFromUrl(value) {
    try {
      const url = new URL(value, window.location.origin);
      const appHost = window.location.hostname.replace(/^www\./, "");
      const inviteHost = url.hostname.replace(/^www\./, "");
      if (url.protocol !== window.location.protocol || inviteHost !== appHost || url.pathname !== "/" || url.search) return "";
      const params = new URLSearchParams(url.hash.slice(1));
      const token = params.get("chat-invite") || "";
      return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : "";
    } catch {
      return "";
    }
  }

  async function createInvite() {
    const button = $("chatCreateInvite");
    const refreshButton = $("chatRefreshInvite");
    const status = $("chatStartStatus");
    button.disabled = true;
    refreshButton.disabled = true;
    status.textContent = "Creating a secure chat QR…";
    status.classList.remove("error");
    try {
      const invite = await api("POST", "/chat/invites", {});
      $("chatInviteQr").src = invite.qrDataUrl;
      $("chatDownloadInvite").href = invite.qrDataUrl;
      $("chatInviteExpiry").textContent = "This QR works for multiple friends until " + new Date(invite.expiresAt).toLocaleString() + ". Creating a new QR replaces it.";
      $("chatInvitePanel").classList.remove("hidden");
      status.textContent = "Your chat QR is ready to share.";
      setStatus("");
    } catch (error) {
      status.textContent = error.message || "Could not create a chat QR. Try again.";
      status.classList.add("error");
      setStatus(error.message, true);
    } finally {
      button.disabled = false;
      refreshButton.disabled = false;
    }
  }

  async function scanInviteImage(file) {
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setStatus("Choose a QR image smaller than 10 MB.", true);
      return;
    }
    let objectUrl = "";
    try {
      let bitmap;
      if (window.createImageBitmap) {
        bitmap = await window.createImageBitmap(file);
      } else {
        objectUrl = URL.createObjectURL(file);
        bitmap = await new Promise((resolve, reject) => {
          const image = new Image();
          image.onload = () => resolve(image);
          image.onerror = () => reject(new Error("Could not open that QR image."));
          image.src = objectUrl;
        });
      }
      if (bitmap.width * bitmap.height > 24000000) {
        bitmap.close?.();
        if (objectUrl) URL.revokeObjectURL(objectUrl);
        throw new Error("That image is too large to scan. Choose a smaller QR image.");
      }
      const canvas = document.createElement("canvas");
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      context.drawImage(bitmap, 0, 0);
      bitmap.close?.();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      const scanned = window.jsQR?.(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
      const token = scanned ? inviteTokenFromUrl(scanned.data) : "";
      if (!token) throw new Error("That image does not contain a valid ClipVault chat QR.");
      setInviteToken(token);
    } catch (error) {
      setStatus(error.message || "Could not read that QR image.", true);
    } finally {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      $("chatQrUpload").value = "";
    }
  }

  function stopInviteCamera() {
    if (qrCameraFrame) cancelAnimationFrame(qrCameraFrame);
    qrCameraFrame = 0;
    qrCameraStream?.getTracks().forEach((track) => track.stop());
    qrCameraStream = null;
    $("chatQrVideo").srcObject = null;
    $("chatCameraPanel").classList.add("hidden");
    $("chatStartCamera").disabled = false;
  }

  async function scanInviteWithCamera() {
    if (!navigator.mediaDevices?.getUserMedia) {
      $("chatStartStatus").textContent = "Camera scanning needs a secure connection. Use HTTPS or upload a QR image.";
      $("chatStartStatus").classList.add("error");
      return;
    }
    $("chatStartCamera").disabled = true;
    try {
      qrCameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      const video = $("chatQrVideo");
      video.srcObject = qrCameraStream;
      $("chatCameraPanel").classList.remove("hidden");
      await video.play();
      const canvas = $("chatQrCanvas");
      const context = canvas.getContext("2d", { willReadFrequently: true });
      const scanFrame = () => {
        if (!qrCameraStream) return;
        if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          context.drawImage(video, 0, 0, canvas.width, canvas.height);
          const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
          const scanned = window.jsQR?.(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
          const token = scanned ? inviteTokenFromUrl(scanned.data) : "";
          if (token) {
            stopInviteCamera();
            setInviteToken(token);
            return;
          }
        }
        qrCameraFrame = requestAnimationFrame(scanFrame);
      };
      $("chatStartStatus").textContent = "Point your camera at a friend’s ClipVault chat QR.";
      $("chatStartStatus").classList.remove("error");
      qrCameraFrame = requestAnimationFrame(scanFrame);
    } catch (error) {
      stopInviteCamera();
      $("chatStartStatus").textContent = error.name === "NotAllowedError"
        ? "Camera access was denied. Allow camera access or upload a QR image."
        : "Could not start the camera. Upload a QR image instead.";
      $("chatStartStatus").classList.add("error");
    }
  }

  async function startChat(event) {
    event.preventDefault();
    if (joiningChat) return;
    const inviteToken = $("chatInviteToken").value;
    const button = $("chatStartForm").querySelector('button[type="submit"]');
    const status = $("chatStartStatus") || $("chatStatus");
    const inlineStatus = status.id === "chatStartStatus";
    if (!inviteToken) {
      status.textContent = "Scan or upload a friend’s chat QR first.";
      status.classList.remove("error");
      return;
    }
    joiningChat = true;
    button.disabled = true;
    button.textContent = "Sending…";
    status.textContent = "Sending invitation…";
    status.classList.remove("error");
    try {
      const result = await api("POST", "/chat/requests", { inviteToken });
      setInviteToken("");
      const message = result.status === "pending"
        ? "Invitation sent. Chat opens after they accept."
        : "Invitation already sent. Waiting for them to accept.";
      status.textContent = message;
      if (!inlineStatus) setStatus(message);
      else window.setTimeout(() => {
        if (status.textContent === message) status.textContent = "";
      }, 3500);
      await refreshChatData();
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("error");
      if (!inlineStatus) setStatus(error.message, true);
    } finally {
      joiningChat = false;
      button.disabled = !$("chatInviteToken").value;
      button.textContent = "Send chat request";
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (sendingMessage || !activeConversation || !activeMessageKey) return;
    const input = $("chatMessageInput");
    const content = input.value.trim();
    if (!content) return;
    const conversation = activeConversation;
    const messageKey = activeMessageKey;
    const pendingId = `pending-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const pendingElement = appendMessage({ id: pendingId, senderId: identity.peerId, createdAt: Date.now(), pending: true }, content);
    input.value = "";
    $("chatMessages").scrollTo({ top: $("chatMessages").scrollHeight, behavior: "smooth" });
    sendingMessage = true;
    stopTyping();
    $("chatSendButton").disabled = true;
    try {
      const encrypted = await crypto.encryptMessage(
        messageKey,
        content,
        conversation.id,
        identity.peerId,
        privateKeys.signing,
      );
      pendingMessagesByCiphertext.set(encrypted.ciphertext, pendingElement);
      const sent = await api("POST", `/chat/conversations/${encodeURIComponent(conversation.id)}/messages`, encrypted);
      if (pendingMessagesByCiphertext.get(encrypted.ciphertext) === pendingElement) {
        reconcilePendingMessage(pendingElement, sent);
        pendingMessagesByCiphertext.delete(encrypted.ciphertext);
      }
    } catch (error) {
      renderedMessageIds.delete(pendingId);
      pendingElement.remove();
      if (!input.value) input.value = content;
      setStatus(error.message, true);
    } finally {
      sendingMessage = false;
      $("chatSendButton").disabled = false;
      input.focus();
    }
  }

  async function deleteConversation() {
    if (!activeConversation) return;
    if (!confirm("Delete this chat and its encrypted message history for both people? This cannot be undone.")) return;
    try {
      await api("DELETE", `/chat/conversations/${encodeURIComponent(activeConversation.id)}`);
      activeConversation = null;
      activeMessageKey = null;
      $("chatActiveThread").classList.add("hidden");
      $("chatThreadEmpty").textContent = "Choose a chat or share a QR to connect.";
      $("chatThreadEmpty").classList.remove("hidden");
      $("chatColumns").classList.add("no-active-chat");
      $("chatColumns").classList.remove("has-active-chat");
      await loadConversations();
      setStatus("Conversation deleted.");
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function initChatNotifications(code) {
    const normalizedCode = String(code).toLowerCase();
    if (normalizedCode !== vaultCode) {
      vaultCode = normalizedCode;
      identity = null;
      privateKeys = null;
      activeConversation = null;
      activeMessageKey = null;
      conversations = [];
      sentRequests = [];
      knownIncomingRequestIds = null;
      clearChatLists();
      $("chatActiveThread").classList.add("hidden");
      $("chatThreadEmpty").classList.remove("hidden");
      showSection("chatSetup");
    }
    $("chatNotificationControl").classList.remove("hidden");
    try {
      await loadRequests();
    } catch (error) {
      setStatus(error.message, true);
    }
    if (!pollTimer) {
      pollTimer = window.setInterval(async () => {
        if (!vaultCode || polling) return;
        polling = true;
        try {
          if (privateKeys) await refreshChatData(false);
          else await loadRequests();
        } catch (error) {
          if (!$("chatPanel").classList.contains("hidden")) setStatus(error.message, true);
        } finally {
          polling = false;
        }
      }, 5000);
    }
    if (!messagePollTimer) {
      messagePollTimer = window.setInterval(async () => {
        if (!activeConversation || messageLoading || document.visibilityState === "hidden"
          || $("chatPanel").classList.contains("hidden")) return;
        try {
          await loadMessages();
        } catch (error) {
          if (!$("chatPanel").classList.contains("hidden")) setStatus(error.message, true);
        }
      }, 750);
    }
  }

  async function initEncryptedChat(code) {
    const normalizedCode = String(code).toLowerCase();
    if (normalizedCode !== vaultCode) {
      vaultCode = normalizedCode;
      identity = null;
      privateKeys = null;
      activeConversation = null;
      activeMessageKey = null;
      conversations = [];
      sentRequests = [];
      knownIncomingRequestIds = null;
      messageCursor = "0";
      clearChatLists();
      $("chatActiveThread").classList.add("hidden");
      $("chatThreadEmpty").classList.remove("hidden");
      showSection("chatSetup");
    }
    setStatus("");
    try {
      if (!identity) await loadIdentity();
      if (privateKeys) await refreshChatData();
    } catch (error) {
      setStatus(error.message, true);
    }
    if (!pollTimer) void initChatNotifications(code);
  }

  $("chatNotificationButton").addEventListener("click", () => {
    const panel = $("chatNotificationPanel");
    const open = panel.classList.contains("hidden");
    panel.classList.toggle("hidden", !open);
    $("chatNotificationButton").setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", (event) => {
    if (!$("chatNotificationControl").contains(event.target)) {
      $("chatNotificationPanel").classList.add("hidden");
      $("chatNotificationButton").setAttribute("aria-expanded", "false");
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      $("chatNotificationPanel").classList.add("hidden");
      $("chatNotificationButton").setAttribute("aria-expanded", "false");
    }
  });
  window.initChatNotifications = initChatNotifications;

  $("chatCreateIdentity").addEventListener("click", beginIdentitySetup);
  $("chatUnlockButton").addEventListener("click", async () => {
    if (!identity?.wrappedPrivateKey?.startsWith("cv2.")) {
      await migrateLegacyIdentity();
      return;
    }
    $("chatUnlockButton").disabled = true;
    try {
      await unlockIdentity(vaultCode);
    } catch {
      setStatus("Could not unlock this chat. Check the vault code and try again.", true);
    } finally {
      $("chatUnlockButton").disabled = false;
    }
  });
  $("chatCreateInvite").addEventListener("click", createInvite);
  $("chatRefreshInvite").addEventListener("click", createInvite);
  $("chatQrUpload").addEventListener("change", (event) => {
    void scanInviteImage(event.target.files?.[0]);
  });
  $("chatStartCamera").addEventListener("click", scanInviteWithCamera);
  $("chatStopCamera").addEventListener("click", stopInviteCamera);
  window.addEventListener("pagehide", stopInviteCamera);
  $("chatStartForm").addEventListener("submit", startChat);
  const urlInvite = inviteTokenFromUrl(window.location.href);
  if (urlInvite) {
    setInviteToken(urlInvite);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  $("chatComposeForm").addEventListener("submit", sendMessage);
  $("chatMessageInput").addEventListener("input", startTyping);
  $("chatMessageInput").addEventListener("blur", stopTyping);
  $("chatMessageInput").addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing || event.keyCode === 229) return;
    event.preventDefault();
    $("chatComposeForm").requestSubmit();
  });
  $("chatDeleteButton").addEventListener("click", deleteConversation);
  $("chatBackButton").addEventListener("click", () => {
    activeConversation = null;
    activeMessageKey = null;
    $("chatActiveThread").classList.add("hidden");
    $("chatThreadEmpty").classList.remove("hidden");
    $("chatColumns").classList.add("no-active-chat");
    $("chatColumns").classList.remove("has-active-chat");
  });

  window.initEncryptedChat = initEncryptedChat;
})();
