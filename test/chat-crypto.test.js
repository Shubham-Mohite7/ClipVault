const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createIdentity,
  decryptMessage,
  deriveConversationKey,
  encryptMessage,
  fingerprint,
  unlockPrivateKey,
} = require("../public/chat-crypto");

test("chat keys encrypt and decrypt messages only for both vault participants", async () => {
  const alice = await createIdentity();
  const bob = await createIdentity();
  const alicePrivateKeys = await unlockPrivateKey(alice, alice.recoveryPhrase);
  const bobPrivateKeys = await unlockPrivateKey(bob, bob.recoveryPhrase);
  const aliceKey = await deriveConversationKey(alicePrivateKeys.agreement, bob.publicKey.agreement, "ABC-123", "XYZ-456");
  const bobKey = await deriveConversationKey(bobPrivateKeys.agreement, alice.publicKey.agreement, "XYZ-456", "ABC-123");
  const message = await encryptMessage(aliceKey, "Private hello 👋", "42", "ABC-123", alicePrivateKeys.signing);
  message.senderCode = "ABC-123";

  assert.equal(await decryptMessage(aliceKey, message, "42", alice.publicKey.signing), "Private hello 👋");
  assert.equal(await decryptMessage(bobKey, message, "42", alice.publicKey.signing), "Private hello 👋");
  const mallory = await createIdentity();
  const malloryPrivateKeys = await unlockPrivateKey(mallory, mallory.recoveryPhrase);
  const malloryKey = await deriveConversationKey(malloryPrivateKeys.agreement, alice.publicKey.agreement, "XYZ-456", "ABC-123");
  await assert.rejects(decryptMessage(malloryKey, message, "42", alice.publicKey.signing));
  await assert.rejects(decryptMessage(bobKey, { ...message, senderCode: "XYZ-456" }, "42", alice.publicKey.signing));
  await assert.rejects(decryptMessage(bobKey, message, "43", alice.publicKey.signing));
});

test("chat recovery phrase protects private key bundle and fingerprints identify public keys", async () => {
  const identity = await createIdentity();
  assert.equal(identity.recoveryPhrase.length, 43);
  const privateKeys = await unlockPrivateKey(identity, identity.recoveryPhrase);
  await assert.rejects(unlockPrivateKey(identity, "incorrect recovery phrase"));
  assert.equal(await fingerprint(identity.publicKey), await fingerprint(identity.publicKey));

  const otherIdentity = await createIdentity();
  assert.notEqual(await fingerprint(identity.publicKey), await fingerprint(otherIdentity.publicKey));
  const key = await deriveConversationKey(privateKeys.agreement, otherIdentity.publicKey.agreement, "ABC-123", "XYZ-456");
  const message = await encryptMessage(key, "Authenticated text", "7", "ABC-123", privateKeys.signing);
  message.senderCode = "ABC-123";
  const modified = {
    iv: message.iv,
    ciphertext: `${message.ciphertext.startsWith("A") ? "B" : "A"}${message.ciphertext.slice(1)}`,
  };
  await assert.rejects(decryptMessage(key, modified, "7", identity.publicKey.signing));
});
