(function attachChatCrypto(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ClipVaultChatCrypto = api;
})(globalThis, () => {
  const cryptoApi = globalThis.crypto
    || (typeof require === "function" ? require("node:crypto").webcrypto : null);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  function bytesToBase64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(bytes).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBytes(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
    if (typeof atob === "function") {
      return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    }
    return new Uint8Array(Buffer.from(padded, "base64"));
  }

  function randomBase64Url(length) {
    const bytes = cryptoApi.getRandomValues(new Uint8Array(length));
    return bytesToBase64Url(bytes);
  }

  async function deriveWrappingKey(recoveryPhrase, salt) {
    const material = await cryptoApi.subtle.importKey(
      "raw",
      encoder.encode(recoveryPhrase),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return cryptoApi.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function createIdentity(vaultCode) {
    const agreementPair = await cryptoApi.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const signingPair = await cryptoApi.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const agreementPublicKey = await cryptoApi.subtle.exportKey("jwk", agreementPair.publicKey);
    const signingPublicKey = await cryptoApi.subtle.exportKey("jwk", signingPair.publicKey);
    const privateKeys = {
      agreement: await cryptoApi.subtle.exportKey("jwk", agreementPair.privateKey),
      signing: await cryptoApi.subtle.exportKey("jwk", signingPair.privateKey),
    };
    const recoveryPhrase = vaultCode ? null : randomBase64Url(32);
    const salt = cryptoApi.getRandomValues(new Uint8Array(16));
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const wrappingSecret = vaultCode ? vaultCode.trim().toUpperCase() : recoveryPhrase;
    const wrappingKey = await deriveWrappingKey(wrappingSecret, salt);
    const wrapped = await cryptoApi.subtle.encrypt(
      { name: "AES-GCM", iv },
      wrappingKey,
      encoder.encode(JSON.stringify(privateKeys)),
    );
    return {
      publicKey: {
        agreement: { kty: agreementPublicKey.kty, crv: agreementPublicKey.crv, x: agreementPublicKey.x, y: agreementPublicKey.y, ext: true, key_ops: [] },
        signing: { kty: signingPublicKey.kty, crv: signingPublicKey.crv, x: signingPublicKey.x, y: signingPublicKey.y, ext: true, key_ops: ["verify"] },
      },
      wrappedPrivateKey: `${vaultCode ? "cv2." : ""}${bytesToBase64Url(new Uint8Array(wrapped))}`,
      recoverySalt: bytesToBase64Url(salt),
      recoveryIv: bytesToBase64Url(iv),
      recoveryPhrase,
    };
  }

  async function unlockPrivateKey(identity, recoveryPhrase) {
    const salt = base64UrlToBytes(identity.recoverySalt);
    const iv = base64UrlToBytes(identity.recoveryIv);
    const codeWrapped = identity.wrappedPrivateKey.startsWith("cv2.");
    const wrappedValue = codeWrapped ? identity.wrappedPrivateKey.slice(4) : identity.wrappedPrivateKey;
    const wrapped = base64UrlToBytes(wrappedValue);
    const wrappingSecret = codeWrapped ? recoveryPhrase.trim().toUpperCase() : recoveryPhrase.trim();
    const wrappingKey = await deriveWrappingKey(wrappingSecret, salt);
    const plaintext = await cryptoApi.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, wrapped);
    const privateJwks = JSON.parse(decoder.decode(plaintext));
    const [agreement, signing] = await Promise.all([
      cryptoApi.subtle.importKey(
        "jwk",
        privateJwks.agreement,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      ),
      cryptoApi.subtle.importKey(
        "jwk",
        privateJwks.signing,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    ]);
    return { agreement, signing };
  }

  async function migrateIdentityToCode(identity, recoveryPhrase, vaultCode) {
    const salt = cryptoApi.getRandomValues(new Uint8Array(16));
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const wrapped = base64UrlToBytes(identity.wrappedPrivateKey);
    const oldKey = await deriveWrappingKey(recoveryPhrase.trim(), base64UrlToBytes(identity.recoverySalt));
    const plaintext = await cryptoApi.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(identity.recoveryIv) },
      oldKey,
      wrapped,
    );
    const nextKey = await deriveWrappingKey(vaultCode.trim().toUpperCase(), salt);
    const nextWrapped = await cryptoApi.subtle.encrypt({ name: "AES-GCM", iv }, nextKey, plaintext);
    return {
      wrappedPrivateKey: `cv2.${bytesToBase64Url(new Uint8Array(nextWrapped))}`,
      recoverySalt: bytesToBase64Url(salt),
      recoveryIv: bytesToBase64Url(iv),
    };
  }

  async function deriveConversationKey(privateKey, peerPublicKey, ownPeerId, peerId) {
    const publicKey = await cryptoApi.subtle.importKey(
      "jwk",
      peerPublicKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedSecret = await cryptoApi.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256,
    );
    const material = await cryptoApi.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
    const participants = [ownPeerId, peerId].sort().join(":");
    return cryptoApi.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode(`ClipVault chat v2:${participants}`),
        info: encoder.encode("message encryption"),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  function signaturePayload(message, conversationId, senderId) {
    return encoder.encode(JSON.stringify({
      conversationId: String(conversationId),
      senderId,
      iv: message.iv,
      ciphertext: message.ciphertext,
    }));
  }

  async function encryptMessage(key, message, conversationId, senderId, signingKey) {
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const additionalData = encoder.encode(
      `ClipVault message v2:${conversationId}:${senderId}`,
    );
    const ciphertext = await cryptoApi.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData },
      key,
      encoder.encode(message),
    );
    const encryptedMessage = {
      iv: bytesToBase64Url(iv),
      ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
    };
    const signature = await cryptoApi.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      signaturePayload(encryptedMessage, conversationId, senderId),
    );
    return { ...encryptedMessage, signature: bytesToBase64Url(new Uint8Array(signature)) };
  }

  async function decryptMessage(key, message, conversationId, senderSigningPublicKey) {
    const signingKey = await cryptoApi.subtle.importKey(
      "jwk",
      senderSigningPublicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const isAuthentic = await cryptoApi.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      base64UrlToBytes(message.signature),
      signaturePayload(message, conversationId, message.senderId),
    );
    if (!isAuthentic) throw new Error("Message signature is invalid");
    const additionalData = encoder.encode(
      `ClipVault message v2:${conversationId}:${message.senderId}`,
    );
    const plaintext = await cryptoApi.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(message.iv), additionalData },
      key,
      base64UrlToBytes(message.ciphertext),
    );
    return decoder.decode(plaintext);
  }

  async function fingerprint(publicKey) {
    const canonicalKey = JSON.stringify(["agreement", "signing"].map((type) => {
      const key = publicKey[type];
      return { type, kty: key.kty, crv: key.crv, x: key.x, y: key.y };
    }));
    const digest = new Uint8Array(await cryptoApi.subtle.digest("SHA-256", encoder.encode(canonicalKey)));
    const hex = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
    return hex.match(/.{1,8}/g).join(" ");
  }

  return {
    createIdentity,
    decryptMessage,
    deriveConversationKey,
    encryptMessage,
    fingerprint,
    migrateIdentityToCode,
    unlockPrivateKey,
  };
});
