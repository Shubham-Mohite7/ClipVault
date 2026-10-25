(() => {
  const crypto = window.ClipVaultChatCrypto;
  const $ = (id) => document.getElementById(id);
  let vaultCode = "";
  let identity = null;
  let privateKeys = null;
  let pendingIdentity = null;
  let ownFingerprint = "";
  let conversations = [];
  let activeConversation = null;
  let activeMessageKey = null;
  let messageCursor = "0";
  let pollTimer = 0;
  let polling = false;

  function setStatus(message, isError = false) {
    $("chatStatus").textContent = message;
    $("chatStatus").classList.toggle("error", isError);
  }

  function showSection(sectionId) {
    for (const id of ["chatSetup", "chatRecoverySetup", "chatUnlock", "chatWorkspace"]) {
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
  }

  async function loadIdentity() {
    identity = await api("GET", "/chat/identity");
    $("chatSetupMessage").textContent = identity.registered
      ? "This vault already has a secure chat identity. Enter its recovery phrase to unlock it on this device."
      : "Set up a secure chat identity for this vault. You will only need to do this once.";
    if (identity.registered) showSection("chatUnlock");
    else showSection("chatSetup");
  }

  async function unlockIdentity(recoveryPhrase) {
    privateKeys = await crypto.unlockPrivateKey(identity, recoveryPhrase);
    ownFingerprint = await crypto.fingerprint(identity.publicKey);
    $("chatOwnFingerprint").textContent = ownFingerprint;
    $("chatRecoveryInput").value = "";
    showSection("chatWorkspace");
    setStatus("Chat unlocked on this device.");
    await refreshChatData();
  }

  async function beginIdentitySetup() {
    $("chatCreateIdentity").disabled = true;
    setStatus("Generating your secure chat identity…");
    try {
      pendingIdentity = await crypto.createIdentity();
      $("chatRecoveryPhrase").textContent = pendingIdentity.recoveryPhrase;
      $("chatRecoveryConfirm").value = "";
      showSection("chatRecoverySetup");
      setStatus("Save your recovery phrase before continuing.");
    } catch (error) {
      setStatus(error.message, true);
    } finally {
      $("chatCreateIdentity").disabled = false;
    }
  }

  async function confirmRecoveryPhrase() {
    if (!pendingIdentity || $("chatRecoveryConfirm").value.trim() !== pendingIdentity.recoveryPhrase) {
      setStatus("The recovery phrase does not match. Copy it exactly before continuing.", true);
      return;
    }
    $("chatConfirmRecovery").disabled = true;
    try {
      const { publicKey, wrappedPrivateKey, recoverySalt, recoveryIv } = pendingIdentity;
      await api("POST", "/chat/identity", { publicKey, wrappedPrivateKey, recoverySalt, recoveryIv });
      identity = {
        registered: true,
        publicKey,
        wrappedPrivateKey,
        recoverySalt,
        recoveryIv,
      };
      const recoveryPhrase = pendingIdentity.recoveryPhrase;
      pendingIdentity = null;
      $("chatRecoveryPhrase").textContent = "";
      $("chatRecoveryConfirm").value = "";
      await unlockIdentity(recoveryPhrase);
      setStatus("Secure chat is ready. Keep your recovery phrase somewhere private.");
    } catch (error) {
      if (error.message.includes("already exists")) {
        pendingIdentity = null;
        await loadIdentity();
      }
      setStatus(error.message, true);
    } finally {
      $("chatConfirmRecovery").disabled = false;
    }
  }

  async function copyRecoveryPhrase() {
    if (!pendingIdentity) return;
    try {
      await navigator.clipboard.writeText(pendingIdentity.recoveryPhrase);
      setStatus("Recovery phrase copied. Store it somewhere private.");
    } catch {
      setStatus("Select and copy the recovery phrase, then store it somewhere private.");
    }
  }

  function appendMessage(message, plaintext) {
    const element = document.createElement("div");
    element.className = `chat-message${message.senderCode === vaultCode.toUpperCase() ? " mine" : ""}`;
    const content = document.createElement("span");
    content.textContent = plaintext;
    const time = document.createElement("time");
    time.dateTime = new Date(message.createdAt).toISOString();
    time.textContent = new Date(message.createdAt).toLocaleString();
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
    if (result.messages.length) $("chatMessages").scrollTop = $("chatMessages").scrollHeight;
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
      setStatus(pinnedFingerprint
        ? "Compare the safety code with your contact if you have not already."
        : "New safety code. Compare it with your contact through another trusted channel.");
      await loadMessages();
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function loadRequests() {
    const result = await api("GET", "/chat/requests");
    const container = $("chatRequests");
    container.replaceChildren();
    if (!result.requests.length) {
      const empty = document.createElement("small");
      empty.textContent = "No pending requests";
      container.append(empty);
      return;
    }
    for (const request of result.requests) {
      const item = document.createElement("div");
      item.className = "chat-list-item";
      const label = document.createElement("span");
      label.textContent = request.senderCode;
      const actions = document.createElement("span");
      for (const [action, title] of [["accept", "Accept"], ["reject", "Decline"]]) {
        const button = document.createElement("button");
        button.className = "link";
        button.type = "button";
        button.textContent = title;
        button.onclick = async () => {
          button.disabled = true;
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
            button.disabled = false;
          }
        };
        actions.append(button);
      }
      item.append(label, actions);
      container.append(item);
    }
  }

  async function loadConversations() {
    const result = await api("GET", "/chat/conversations");
    conversations = result.conversations;
    const container = $("chatConversations");
    container.replaceChildren();
    if (!conversations.length) {
      const empty = document.createElement("small");
      empty.textContent = "No chats yet";
      container.append(empty);
      return;
    }
    for (const conversation of conversations) {
      const button = document.createElement("button");
      button.className = "chat-list-item";
      button.type = "button";
      button.textContent = conversation.peerCode;
      button.onclick = () => selectConversation(conversation);
      container.append(button);
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
          setStatus("Warning: the saved safety code for this contact changed.", true);
        } else {
          activeConversation = updated;
        }
      }
    }
  }

  async function refreshChatData() {
    if (!privateKeys || $("chatPanel").classList.contains("hidden")) return;
    await Promise.all([loadRequests(), loadConversations()]);
    await loadMessages();
  }

  async function startChat(event) {
    event.preventDefault();
    const recipientCode = $("chatRecipientCode").value.trim().toUpperCase();
    try {
      const result = await api("POST", "/chat/requests", { recipientCode });
      $("chatRecipientCode").value = "";
      setStatus(result.status === "pending" ? "Chat request sent. The other person must accept it." : "Request is already pending.");
      await loadConversations();
    } catch (error) {
      setStatus(error.message, true);
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
      await loadConversations();
      setStatus("Chat and its message history deleted.");
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function initEncryptedChat(code) {
    const normalizedCode = String(code).toLowerCase();
    if (normalizedCode !== vaultCode) {
      vaultCode = normalizedCode;
      identity = null;
      privateKeys = null;
      pendingIdentity = null;
      activeConversation = null;
      activeMessageKey = null;
      conversations = [];
      messageCursor = "0";
      clearChatLists();
      $("chatActiveThread").classList.add("hidden");
      $("chatThreadEmpty").classList.remove("hidden");
      showSection("chatSetup");
    }
    setStatus("Loading secure chat…");
    try {
      if (!identity) await loadIdentity();
      if (privateKeys) await refreshChatData();
    } catch (error) {
      setStatus(error.message, true);
    }
    if (!pollTimer) {
      pollTimer = window.setInterval(async () => {
        if (privateKeys && !$("chatPanel").classList.contains("hidden") && !polling) {
          polling = true;
          try { await refreshChatData(); }
          catch (error) { setStatus(error.message, true); }
          finally { polling = false; }
        }
      }, 5000);
    }
  }

  $("chatCreateIdentity").addEventListener("click", beginIdentitySetup);
  $("chatCopyRecovery").addEventListener("click", copyRecoveryPhrase);
  $("chatConfirmRecovery").addEventListener("click", confirmRecoveryPhrase);
  $("chatUnlockButton").addEventListener("click", async () => {
    $("chatUnlockButton").disabled = true;
    try {
      await unlockIdentity($("chatRecoveryInput").value);
    } catch {
      setStatus("Could not unlock this identity. Check your recovery phrase and try again.", true);
    } finally {
      $("chatUnlockButton").disabled = false;
    }
  });
  $("chatStartForm").addEventListener("submit", startChat);
  $("chatComposeForm").addEventListener("submit", sendMessage);
  $("chatDeleteButton").addEventListener("click", deleteConversation);

  window.initEncryptedChat = initEncryptedChat;
})();
