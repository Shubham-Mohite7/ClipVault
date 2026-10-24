const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createSignedState,
  decryptRefreshToken,
  encryptRefreshToken,
  verifySignedState,
} = require("../drive-security");
const { validateUpload } = require("../drive-files");

const key = Buffer.alloc(32, 7);

test("refresh token encryption round-trips and uses a fresh IV", () => {
  const encrypted = encryptRefreshToken("refresh-token", key);
  assert.equal(decryptRefreshToken(encrypted, key), "refresh-token");
  assert.notEqual(encrypted, encryptRefreshToken("refresh-token", key));
});

test("tampered encrypted refresh token is rejected", () => {
  const encrypted = Buffer.from(encryptRefreshToken("refresh-token", key), "base64");
  encrypted[encrypted.length - 1] ^= 1;
  assert.throws(() => decryptRefreshToken(encrypted.toString("base64"), key));
});

test("OAuth state accepts valid, rejects expired and tampered states", () => {
  const now = 1_800_000_000_000;
  const state = createSignedState("01234", key, now);
  assert.equal(verifySignedState(state, key, now).code, "01234");
  assert.throws(() => verifySignedState(state, key, now + 601_000));
  const [payload, signature] = state.split(".");
  const tamperedPayload = `${payload[0] === "a" ? "b" : "a"}${payload.slice(1)}`;
  const tampered = `${tamperedPayload}.${signature}`;
  assert.throws(() => verifySignedState(tampered, key, now));
});

test("upload validation rejects wrong signatures, oversized data, and SVG", () => {
  assert.throws(
    () => validateUpload("image/png", Buffer.from("not png"), "wrong.png"),
    { status: 400 },
  );
  assert.throws(
    () => validateUpload("image/png", Buffer.alloc(5 * 1024 * 1024), "large.png"),
    { status: 413 },
  );
  assert.throws(
    () => validateUpload("image/svg+xml", Buffer.from("<svg/>"), "image.svg"),
    { status: 400 },
  );
});
