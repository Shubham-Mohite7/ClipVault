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

  async function createIdentity() {
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
    const recoveryPhrase = randomBase64Url(32);
    const salt = cryptoApi.getRandomValues(new Uint8Array(16));
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const wrappingKey = await deriveWrappingKey(recoveryPhrase, salt);
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
      wrappedPrivateKey: bytesToBase64Url(new Uint8Array(wrapped)),
      recoverySalt: bytesToBase64Url(salt),
      recoveryIv: bytesToBase64Url(iv),
      recoveryPhrase,
    };
  }

  async function unlockPrivateKey(identity, recoveryPhrase) {
    const salt = base64UrlToBytes(identity.recoverySalt);
    const iv = base64UrlToBytes(identity.recoveryIv);
    const wrapped = base64UrlToBytes(identity.wrappedPrivateKey);
    const wrappingKey = await deriveWrappingKey(recoveryPhrase.trim(), salt);
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

  async function deriveConversationKey(privateKey, peerPublicKey, ownCode, peerCode) {
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
    const participants = [ownCode.toUpperCase(), peerCode.toUpperCase()].sort().join(":");
    return cryptoApi.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode(`ClipVault chat v1:${participants}`),
        info: encoder.encode("message encryption"),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  function signaturePayload(message, conversationId, senderCode) {
    return encoder.encode(JSON.stringify({
      conversationId: String(conversationId),
      senderCode: senderCode.toUpperCase(),
      iv: message.iv,
      ciphertext: message.ciphertext,
    }));
  }

  async function encryptMessage(key, message, conversationId, senderCode, signingKey) {
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const additionalData = encoder.encode(
      `ClipVault message v1:${conversationId}:${senderCode.toUpperCase()}`,
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
      signaturePayload(encryptedMessage, conversationId, senderCode),
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
      signaturePayload(message, conversationId, message.senderCode),
    );
    if (!isAuthentic) throw new Error("Message signature is invalid");
    const additionalData = encoder.encode(
      `ClipVault message v1:${conversationId}:${message.senderCode.toUpperCase()}`,
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
    unlockPrivateKey,
  };
});
