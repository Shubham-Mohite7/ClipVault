const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createSignedState,
  decryptRefreshToken,
  encryptRefreshToken,
  verifySignedState,
} = require("../drive-security");
const { trashTrackedFiles, validateUpload } = require("../drive-files");

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

test("disconnect trashes each tracked file before removing its reference", async () => {
  const calls = [];
  const count = await trashTrackedFiles(
    [
      { id: 1, driveFileId: "drive-1" },
      { id: 2, driveFileId: "drive-2" },
    ],
    async (id) => calls.push(`trash:${id}`),
    async (id) => calls.push(`remove:${id}`),
  );

  assert.equal(count, 2);
  assert.deepEqual(calls, ["trash:drive-1", "remove:1", "trash:drive-2", "remove:2"]);
});

test("disconnect stops when a Drive file cannot be trashed", async () => {
  const calls = [];
  await assert.rejects(
    trashTrackedFiles(
      [
        { id: 1, driveFileId: "drive-1" },
        { id: 2, driveFileId: "drive-2" },
        { id: 3, driveFileId: "drive-3" },
      ],
      async (id) => {
        calls.push(`trash:${id}`);
        if (id === "drive-2") throw new Error("Google Drive error");
      },
      async (id) => calls.push(`remove:${id}`),
    ),
    /Google Drive error/,
  );

  assert.deepEqual(calls, ["trash:drive-1", "remove:1", "trash:drive-2"]);
});
