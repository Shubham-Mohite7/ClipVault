const crypto = require("crypto");

const VAULT_CODE_PATTERN = /^(?:\d{5}|[a-z]{3}-\d{3})$/;

function normalizeVaultCode(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isValidVaultCode(value) {
  return VAULT_CODE_PATTERN.test(normalizeVaultCode(value));
}

function createVaultCode() {
  const letters = Array.from({ length: 3 }, () => String.fromCharCode(65 + crypto.randomInt(26))).join("");
  const digits = String(crypto.randomInt(1000)).padStart(3, "0");
  return `${letters}-${digits}`;
}

module.exports = { createVaultCode, isValidVaultCode, normalizeVaultCode };
