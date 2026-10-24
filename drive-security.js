const crypto = require("crypto");
const { isValidVaultCode, normalizeVaultCode } = require("./vault-codes");

function encryptionKey(value = process.env.TOKEN_ENC_KEY) {
  if (!/^[a-f\d]{64}$/i.test(value || "")) {
    const error = new Error("Drive not configured");
    error.code = "DRIVE_NOT_CONFIGURED";
    throw error;
  }
  return Buffer.from(value, "hex");
}

function encryptRefreshToken(token, key = encryptionKey()) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64");
}

function decryptRefreshToken(encrypted, key = encryptionKey()) {
  const value = Buffer.from(encrypted, "base64");
  if (value.length < 28) throw new Error("Invalid encrypted token");
  const iv = value.subarray(0, 12);
  const tag = value.subarray(12, 28);
  const ciphertext = value.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function stateSigningKey(key = encryptionKey()) {
  return crypto.createHmac("sha256", key).update("clipvault-drive-oauth-state").digest();
}

function createSignedState(code, key = encryptionKey(), now = Date.now()) {
  if (!isValidVaultCode(code) || normalizeVaultCode(code) !== code) {
    throw new Error("Invalid vault code");
  }
  const payload = Buffer.from(JSON.stringify({
    code,
    nonce: crypto.randomBytes(16).toString("base64url"),
    exp: Math.floor(now / 1000) + 600,
  })).toString("base64url");
  const signature = crypto.createHmac("sha256", stateSigningKey(key)).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verifySignedState(state, key = encryptionKey(), now = Date.now()) {
  if (typeof state !== "string") throw new Error("Invalid state");
  const parts = state.split(".");
  if (parts.length !== 2 || !/^[\w-]+$/.test(parts[0]) || !/^[\w-]+$/.test(parts[1])) {
    throw new Error("Invalid state");
  }

  const expected = crypto.createHmac("sha256", stateSigningKey(key)).update(parts[0]).digest();
  const actual = Buffer.from(parts[1], "base64url");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new Error("Invalid state");
  }

  const payload = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (!isValidVaultCode(payload.code) || normalizeVaultCode(payload.code) !== payload.code
      || typeof payload.nonce !== "string"
      || !payload.nonce || !Number.isInteger(payload.exp) || payload.exp <= Math.floor(now / 1000)) {
    throw new Error("Invalid state");
  }
  return payload;
}

module.exports = {
  createSignedState,
  decryptRefreshToken,
  encryptRefreshToken,
  encryptionKey,
  verifySignedState,
};
