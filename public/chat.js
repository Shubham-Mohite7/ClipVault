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
  let polling = false;
  let statusTimer = 0;
  let joiningChat = false;
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
      await api("POST", "/chat/identity", { publicKey, wrappedPrivateKey, recoverySalt, recoveryIv });
      identity = { registered: true, publicKey, wrappedPrivateKey, recoverySalt, recoveryIv };
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
    element.className = `chat-message${message.senderCode === vaultCode.toUpperCase() ? " mine" : ""}`;
    const content = document.createElement("span");
    content.textContent = plaintext;
    const time = document.createElement("time");
    time.dateTime = new Date(message.createdAt).toISOString();
    time.textContent = new Date(message.createdAt).toLocaleTimeString(undefined, {
      hour: "numeric",
      minute: "2-digit",
    });
    time.title = new Date(message.createdAt).toLocaleString();
    element.append(content, time);
    $("chatMessages").append(element);
  }

  async function loadMessages() {
    if (!activeConversation || !activeMessageKey) return;
    const result = await api(
      "GET",
      `/chat/conversations/${encodeURIComponent(activeConversation.id)}/messages?after=${encodeURIComponent(messageCursor)}`,
    );
    for (const message of result.messages) {
      messageCursor = message.id;
      try {
        appendMessage(
          message,
          await crypto.decryptMessage(
            activeMessageKey,
            message,
            activeConversation.id,
            message.senderCode === vaultCode.toUpperCase()
              ? identity.publicKey.signing
              : activeConversation.peerPublicKey.signing,
          ),
        );
      } catch {
        appendMessage(message, "Could not decrypt this message. Check the safety code with your contact.");
      }
    }
    if (result.messages.length) {
      const messageList = $("chatMessages");
      messageList.scrollTo({
        top: messageList.scrollHeight,
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      });
    }
  }

  async function selectConversation(conversation) {
    try {
      const peerFingerprint = await crypto.fingerprint(conversation.peerPublicKey);
      const pinKey = `clipvault-chat-peer:${vaultCode}:${conversation.peerCode}`;
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
        vaultCode,
        conversation.peerCode.toLowerCase(),
      );
      messageCursor = "0";
      $("chatPeerCode").textContent = conversation.peerCode;
      $("chatPeerFingerprint").textContent = peerFingerprint;
      $("chatMessages").replaceChildren();
      $("chatThreadEmpty").classList.add("hidden");
      $("chatActiveThread").classList.remove("hidden");
      $("chatColumns").classList.remove("no-active-chat");
      $("chatColumns").classList.add("has-active-chat");
      setStatus("");
      await loadMessages();
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
      label.textContent = `Request from ${request.senderCode}`;
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
          if (typeof window.toast === "function") window.toast(`New chat request from ${request.senderCode}`);
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
      code.textContent = request.senderCode;
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
    const conversationsByPeer = new Map(conversations.map((conversation) => [conversation.peerCode.toUpperCase(), conversation]));
    const statusLabels = { pending: "Waiting", accepted: "Accepted", rejected: "Declined" };
    const items = [
      ...conversations.map((conversation) => ({
        peerCode: conversation.peerCode,
        conversation,
        request: sentRequests.find((item) => item.peerCode.toUpperCase() === conversation.peerCode.toUpperCase()),
        createdAt: conversation.createdAt,
      })),
      ...sentRequests
        .filter((request) => !conversationsByPeer.has(request.peerCode.toUpperCase()))
        .map((request) => ({ peerCode: request.peerCode, request, createdAt: request.createdAt })),
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
      peer.textContent = item.peerCode;
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
        const pinKey = `clipvault-chat-peer:${vaultCode}:${updated.peerCode}`;
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

  async function refreshChatData() {
    if (!privateKeys) return;
    await loadRequests();
    await loadConversations();
    if (!$("chatPanel").classList.contains("hidden")) await loadMessages();
  }

  function readRecipientCode() {
    const entry = $("chatCodeEntry");
    const slots = [...entry.querySelectorAll(".chat-code-slot")];
    const values = slots.map((slot) => slot.value);
    const numeric = entry.classList.contains("is-numeric");
    if (numeric) return values.slice(0, 5).every(Boolean) ? values.slice(0, 5).join("") : "";
    return values.slice(0, 6).every(Boolean)
      ? `${values.slice(0, 3).join("")}-${values.slice(3, 6).join("")}`
      : "";
  }

  function clearRecipientCode() {
    const entry = $("chatCodeEntry");
    for (const slot of entry.querySelectorAll(".chat-code-slot")) slot.value = "";
    entry.classList.remove("is-numeric");
    $("chatRecipientCode").value = "";
  }

  function fillRecipientCode(value, startAt = 0) {
    const entry = $("chatCodeEntry");
    const slots = [...entry.querySelectorAll(".chat-code-slot")];
    const compact = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
    const isNumeric = /^\d/.test(compact);
    entry.classList.toggle("is-numeric", isNumeric);
    for (const slot of slots) slot.value = "";
    if (isNumeric) {
      compact.replace(/\D/g, "").slice(0, 5).split("").forEach((char, index) => { slots[index].value = char; });
    } else {
      const letters = (compact.match(/^[A-Z]{0,3}/) || [""])[0];
      const digits = compact.slice(letters.length).replace(/\D/g, "").slice(0, 3);
      [...letters, ...digits].forEach((char, index) => { slots[index].value = char; });
    }
    const completed = readRecipientCode();
    $("chatRecipientCode").value = completed;
    const firstEmpty = slots.findIndex((slot, index) => !slot.value && (isNumeric ? index < 5 : index < 6));
    const focusIndex = firstEmpty < 0 ? Math.min(startAt, slots.length - 1) : firstEmpty;
    slots[focusIndex]?.focus();
    return completed;
  }

  async function startChat(event) {
    event.preventDefault();
    if (joiningChat) return;
    const recipientCode = readRecipientCode();
    const button = $("chatStartForm").querySelector('button[type="submit"]');
    const status = $("chatStartStatus") || $("chatStatus");
    const inlineStatus = status.id === "chatStartStatus";
    if (!recipientCode) {
      status.textContent = "Enter all code characters first.";
      status.classList.remove("error");
      return;
    }
    joiningChat = true;
    button.disabled = true;
    button.textContent = "Sending…";
    status.textContent = "Sending invitation…";
    status.classList.remove("error");
    try {
      const result = await api("POST", "/chat/requests", { recipientCode });
      clearRecipientCode();
      const message = result.status === "pending"
        ? "Invitation sent. Chat opens after they accept."
        : "Invitation already sent. Waiting for them to accept.";
      status.textContent = message;
      if (!inlineStatus) setStatus(message);
      else window.setTimeout(() => {
        if (status.textContent === message) status.textContent = "";
      }, 3500);
      await loadConversations();
    } catch (error) {
      status.textContent = error.message;
      status.classList.add("error");
      if (!inlineStatus) setStatus(error.message, true);
    } finally {
      joiningChat = false;
      button.disabled = false;
      button.textContent = "Start chat";
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (!activeConversation || !activeMessageKey) return;
    const input = $("chatMessageInput");
    const content = input.value.trim();
    if (!content) return;
    $("chatSendButton").disabled = true;
    try {
      const encrypted = await crypto.encryptMessage(
        activeMessageKey,
        content,
        activeConversation.id,
        vaultCode,
        privateKeys.signing,
      );
      await api("POST", `/chat/conversations/${encodeURIComponent(activeConversation.id)}/messages`, encrypted);
      input.value = "";
      await loadMessages();
    } catch (error) {
      setStatus(error.message, true);
    } finally {
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
      $("chatThreadEmpty").textContent = "Choose a chat or enter a vault code to start one.";
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
          if (privateKeys) await refreshChatData();
          else await loadRequests();
        } catch (error) {
          if (!$("chatPanel").classList.contains("hidden")) setStatus(error.message, true);
        } finally {
          polling = false;
        }
      }, 5000);
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
  $("chatStartForm").addEventListener("submit", startChat);
  const codeEntry = $("chatCodeEntry");
  const codeSlots = [...codeEntry.querySelectorAll(".chat-code-slot")];
  codeSlots.forEach((slot, index) => {
    slot.addEventListener("input", () => {
      const entryIsNumeric = codeEntry.classList.contains("is-numeric");
      const raw = slot.value.toUpperCase().replace(/[^A-Z0-9]/g, "");
      if (index === 0 && raw) codeEntry.classList.toggle("is-numeric", /\d/.test(raw[0]));
      const numeric = codeEntry.classList.contains("is-numeric");
      const allowed = numeric ? /\d/ : index < 3 ? /[A-Z]/ : /\d/;
      const character = raw.split("").find((item) => allowed.test(item)) || "";
      slot.value = character;
      const code = readRecipientCode();
      $("chatRecipientCode").value = code;
      const status = $("chatStartStatus");
      status.textContent = "";
      status.classList.remove("error");
      if (character && index < (numeric ? 4 : 5)) {
        const nextSlot = codeSlots[index + 1];
        requestAnimationFrame(() => {
          nextSlot.focus({ preventScroll: true });
          nextSlot.select();
        });
      }
      if (code && !joiningChat) $("chatStartForm").requestSubmit();
      if (entryIsNumeric && !numeric) codeEntry.classList.remove("is-numeric");
    });
    slot.addEventListener("paste", (event) => {
      const pasted = event.clipboardData?.getData("text") || "";
      if (!pasted) return;
      event.preventDefault();
      const complete = fillRecipientCode(pasted, index);
      $("chatStartStatus").textContent = "";
      $("chatStartStatus").classList.remove("error");
      if (complete && !joiningChat) $("chatStartForm").requestSubmit();
    });
    slot.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !slot.value && index > 0) {
        event.preventDefault();
        codeSlots[index - 1].value = "";
        $("chatRecipientCode").value = readRecipientCode();
        codeSlots[index - 1].focus();
      } else if (event.key === "ArrowLeft" && index > 0) {
        event.preventDefault();
        codeSlots[index - 1].focus();
      } else if (event.key === "ArrowRight" && index < codeSlots.length - 1) {
        event.preventDefault();
        codeSlots[index + 1].focus();
      }
    });
  });
  $("chatComposeForm").addEventListener("submit", sendMessage);
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
