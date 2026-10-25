const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "clipvault-drive-test-"));
process.env.DB_PATH = path.join(tempDir, "test.db");
delete process.env.DATABASE_URL;
delete process.env.VERCEL;
delete process.env.GOOGLE_CLIENT_ID;
delete process.env.GOOGLE_CLIENT_SECRET;
delete process.env.GOOGLE_REDIRECT_URI;
delete process.env.TOKEN_ENC_KEY;

const legacyDb = new Database(process.env.DB_PATH);
legacyDb.exec(`
  CREATE TABLE vaults (
    code TEXT PRIMARY KEY CHECK (length(code) = 5),
    created_at INTEGER NOT NULL,
    last_used INTEGER NOT NULL
  );
  CREATE TABLE snippets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  INSERT INTO vaults VALUES ('12345', 1, 1);
  INSERT INTO snippets (vault_code, title, content, created_at, updated_at)
    VALUES ('12345', 'Legacy', 'Still here', 1, 1);
`);
legacyDb.close();

const app = require("../server");

test("SQLite APIs work and Drive routes and upload validation are safe", async (t) => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (url, options) => fetch(`${base}${url}`, options);
  const home = await request("/");
  assert.equal(home.status, 200);
  const homeText = await home.text();
  assert.match(homeText, /ClipVault/);
  assert.match(homeText, /<title>ClipVault: Free Online Clipboard/);
  assert.match(homeText, /name="description"/);
  assert.match(homeText, /rel="manifest" href="\/manifest\.webmanifest"/);
  assert.match(homeText, /apple-mobile-web-app-capable/);
  assert.match(homeText, /id="installApp"/);
  assert.match(homeText, /function showApp\(loading = false\)[\s\S]*?\$\("installApp"\)\.classList\.add\("hidden"\)/);
  assert.match(homeText, /beforeinstallprompt/);
  assert.match(homeText, /Add to Home Screen/);
  assert.match(homeText, /serviceWorker\.register\("\/service-worker\.js"\)/);
  assert.match(homeText, /id="chatTab" role="tab"/);
  assert.match(homeText, /id="chatPanel" class="hidden"/);
  assert.match(homeText, /Messages are encrypted on your device before they reach the server/);
  assert.match(homeText, /Compare safety codes with your contact through another trusted channel/);
  assert.match(homeText, /src="\/chat-crypto\.js" defer/);
  assert.match(homeText, /src="\/chat\.js" defer/);
  assert.match(homeText, /Save text, images, and PDFs/);
  assert.match(homeText, /No account needed/);
  assert.match(homeText, /Attachments stay in Google Drive/);
  assert.match(homeText, /Save text, images, and PDFs\. Open your vault anywhere with a code\. No account needed\./);
  assert.match(homeText, /Images and PDFs stay in your Google Drive/);
  assert.match(homeText, /\"description\": \"A free online clipboard for saving text snippets and attaching images and PDFs in Google Drive/);
  assert.match(homeText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/"/);
  assert.match(homeText, /property="og:title"/);
  assert.match(homeText, /A simple online clipboard for your snippets/);
  assert.match(homeText, /Save snippets and open them on any device with your code\. No account required\./);
  const structuredData = homeText.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(structuredData, "homepage should include WebApplication structured data");
  assert.equal(JSON.parse(structuredData[1])["@type"], "WebApplication");
  assert.match(homeText, /href="\/privacy\.html"/);
  assert.match(homeText, /href="\/terms\.html"/);
  assert.match(homeText, /id="themeToggle"/);
  assert.match(homeText, /clipvault-theme/);
  assert.match(homeText, /--theme-motion: 420ms cubic-bezier\(\.22, 1, \.36, 1\)/);
  assert.match(homeText, /\* \{ transition: color var\(--theme-motion\), background-color var\(--theme-motion\), border-color var\(--theme-motion\), box-shadow var\(--theme-motion\); \}/);
  assert.match(homeText, /transition-duration: \.01ms !important/);
  assert.match(homeText, /window\.vaq/);
  assert.match(homeText, /src="\/_vercel\/insights\/script\.js"/);
  assert.match(homeText, /function renderSnippetSkeleton\(\)/);
  assert.match(homeText, /code-check-spin/);
  assert.match(homeText, /Checking your code/);
  assert.match(homeText, /Code found\. Opening your vault/);
  assert.match(homeText, /id="err" role="status" aria-live="polite"/);
  const codeEntryHandler = homeText.slice(
    homeText.indexOf("async function enterCode(c)"),
    homeText.indexOf('$("create").onclick'),
  );
  const codeCheckIndex = codeEntryHandler.indexOf("/check");
  const loadingIndex = codeEntryHandler.indexOf("showApp(true)");
  const snippetsIndex = codeEntryHandler.indexOf("/snippets");
  assert.ok(codeCheckIndex >= 0 && codeCheckIndex < loadingIndex && loadingIndex < snippetsIndex);
  assert.match(homeText, /function renderFileSkeleton\(\)/);
  assert.match(homeText, /aria-label="Checking Google Drive"/);
  assert.match(homeText, /aria-label="Loading files"/);
  assert.match(homeText, /id="uploadProgress" class="upload-progress hidden"/);
  assert.match(homeText, /id="uploadProgressBar" max="100" value="0" aria-label="Overall upload progress"/);
  assert.match(homeText, /function uploadFile\(file, onProgress\)/);
  assert.match(homeText, /xhr\.upload\.onprogress/);
  assert.match(homeText, /formatFileSize\(fileBytesSent\)\} of \$\{formatFileSize\(file\.size\)\}/);
  assert.match(homeText, /Overall upload progress/);
  assert.match(homeText, /Uploaded \$\{uploadedCount\} of \$\{validFiles\.length\}/);
  assert.match(homeText, /\.file-actions \{ display: flex; flex-wrap: wrap; align-items: center/);
  assert.match(homeText, /\.file-actions button\.link \{ margin-left: auto; padding-inline: 4px; \}/);
  assert.match(homeText, /card\.setAttribute\("aria-label", `File \$\{file\.name\}\. Activate the card to open\.`\)/);
  assert.match(homeText, /if \(event\.target\.closest\("a, button"\)\) return/);
  assert.match(homeText, /event\.key !== "Enter" && event\.key !== " "/);
  assert.match(homeText, /\.file-card\[tabindex="0"\]:focus-visible/);
  assert.match(homeText, /placeholder="A" aria-label="Code character 1"/);
  assert.match(homeText, /placeholder="0" aria-label="Code character 6"/);
  assert.match(homeText, /\.reveal \{[\s\S]*?backdrop-filter: blur\(28px\) saturate\(1\.5\)/);
  assert.match(homeText, /\.reveal \{ width: calc\(100% - 28px\); margin-top: 36px; padding: 40px 20px 36px/);
  assert.doesNotMatch(homeText, /Your last used code is filled in/);
  assert.match(homeText, /id="openVault" class="btn small secondary hidden"/);
  assert.match(homeText, /function saveRememberedCode\(value\)/);
  assert.match(homeText, /if \(value && value !== rememberedSuggestion\) enterCode\(value\)/);
  assert.match(homeText, /rememberedSuggestion = candidate/);
  assert.match(homeText, /dismissRememberedSuggestion\(\)/);
  assert.match(homeText, /Restore the current vault after OAuth/);
  assert.doesNotMatch(homeText, /Auto sign-in on this device/);
  const signOutHandler = homeText.slice(
    homeText.indexOf('$("logout").onclick'),
    homeText.indexOf("function setActiveTab"),
  );
  assert.doesNotMatch(signOutHandler, /removeItem\(KEY\)/);
  assert.match(homeText, /id="newCode">ABC-123/);
  assert.match(homeText, /move every file uploaded through this ClipVault vault to Google Drive Trash/);
  assert.match(homeText, /POST", "\/api\/drive\/restore"/);
  assert.match(homeText, /driveReturnTicket/);
  assert.match(homeText, /history\.replaceState\(null, "", location\.pathname\)/);
  assert.match(homeText, /new URLSearchParams\(location\.hash\.slice\(1\)\)\.get\("return"\)/);

  const privacy = await request("/privacy.html");
  assert.equal(privacy.status, 200);
  const privacyText = await privacy.text();
  assert.match(privacyText, /Privacy Policy/);
  assert.match(privacyText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/privacy\.html"/);
  assert.match(privacyText, /drive\.file/);
  assert.match(privacyText, /contact\.mohite@gmail\.com/);
  assert.match(privacyText, /Website analytics/);
  assert.match(privacyText, /vercel\.com\/docs\/analytics\/privacy-policy/);
  assert.match(privacyText, /moves all tracked ClipVault attachments/);
  assert.match(privacyText, /hashed, single-use return ticket linked to the vault/);
  assert.match(privacyText, /expires after five minutes and is deleted when used/);
  assert.match(privacyText, /connection remains active so you can retry/);
  assert.match(privacyText, /src="\/_vercel\/insights\/script\.js"/);
  assert.match(privacyText, /Your recovery phrase and message plaintext are not sent to ClipVault/);
  assert.match(privacyText, /does not provide forward secrecy/);

  const terms = await request("/terms.html");
  assert.equal(terms.status, 200);
  const termsText = await terms.text();
  assert.match(termsText, /Terms of Service/);
  assert.match(termsText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/terms\.html"/);
  assert.match(termsText, /ABC-123/);
  assert.match(termsText, /existing five-digit codes/);
  assert.match(termsText, /Google Drive/);
  assert.match(termsText, /moves its tracked ClipVault attachments to Google Drive Trash/);
  assert.match(termsText, /contact\.mohite@gmail\.com/);
  assert.match(termsText, /src="\/_vercel\/insights\/script\.js"/);
  assert.match(termsText, /If you lose it, ClipVault cannot restore the identity/);
  assert.match(termsText, /does not provide forward secrecy/);

  const robots = await request("/robots.txt");
  assert.equal(robots.status, 200);
  const robotsText = await robots.text();
  assert.match(robotsText, /Disallow: \/api\//);
  assert.match(robotsText, /Sitemap: https:\/\/www\.clipvault\.lol\/sitemap\.xml/);

  const sitemap = await request("/sitemap.xml");
  assert.equal(sitemap.status, 200);
  const sitemapText = await sitemap.text();
  assert.match(sitemapText, /https:\/\/www\.clipvault\.lol\//);
  assert.match(sitemapText, /https:\/\/www\.clipvault\.lol\/privacy\.html/);
  assert.match(sitemapText, /https:\/\/www\.clipvault\.lol\/terms\.html/);

  const manifestResponse = await request("/manifest.webmanifest");
  assert.equal(manifestResponse.status, 200);
  const manifest = await manifestResponse.json();
  assert.equal(manifest.name, "ClipVault — Online Clipboard");
  assert.equal(manifest.display, "standalone");
  assert.deepEqual(manifest.icons.map(({ sizes }) => sizes), ["192x192", "512x512"]);

  for (const iconPath of ["/icons/icon-192.png", "/icons/icon-512.png", "/icons/apple-touch-icon.png"]) {
    const icon = await request(iconPath);
    assert.equal(icon.status, 200, iconPath);
    assert.match(icon.headers.get("content-type"), /image\/png/);
    assert.ok(Number(icon.headers.get("content-length")) > 0);
  }

  const serviceWorker = await request("/service-worker.js");
  assert.equal(serviceWorker.status, 200);
  const serviceWorkerText = await serviceWorker.text();
  assert.match(serviceWorkerText, /url\.pathname\.startsWith\("\/api\/"\)/);
  assert.match(serviceWorkerText, /url\.pathname\.startsWith\("\/_vercel\/"\)/);
  assert.match(serviceWorkerText, /clipvault-shell-v3/);
  assert.match(serviceWorkerText, /"\/chat-crypto\.js"/);
  assert.match(serviceWorkerText, /"\/chat\.js"/);
  for (const scriptPath of ["/chat-crypto.js", "/chat.js"]) {
    const script = await request(scriptPath);
    assert.equal(script.status, 200, scriptPath);
    assert.match(script.headers.get("content-type"), /javascript/);
  }

  const health = await request("/healthz");
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { ok: true });

  const legacyList = await request("/api/vaults/12345/snippets");
  assert.equal(legacyList.status, 200);
  assert.deepEqual((await legacyList.json()).snippets.map(({ title, content }) => ({ title, content })), [
    { title: "Legacy", content: "Still here" },
  ]);
  assert.deepEqual(await (await request("/api/vaults/12345/check")).json(), { valid: true });

  const created = await request("/api/vaults", { method: "POST" });
  assert.equal(created.status, 201);
  const { code } = await created.json();
  assert.match(code, /^[A-Z]{3}-\d{3}$/);
  const validCodeCheck = await request(`/api/vaults/${code}/check`);
  assert.equal(validCodeCheck.status, 200);
  assert.deepEqual(await validCodeCheck.json(), { valid: true });
  assert.equal((await request("/api/vaults/99999x/check")).status, 404);
  assert.equal((await request("/api/vaults/abc-999/check")).status, 404);

  const makeChatVault = async () => {
    const response = await request("/api/vaults", { method: "POST" });
    assert.equal(response.status, 201);
    return (await response.json()).code;
  };
  const [chatSender, chatRecipient, chatOutsider] = await Promise.all([
    makeChatVault(), makeChatVault(), makeChatVault(),
  ]);
  const makeChatIdentity = () => {
    const agreementPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const signingPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    return {
      publicKey: {
        agreement: agreementPair.publicKey.export({ format: "jwk" }),
        signing: signingPair.publicKey.export({ format: "jwk" }),
      },
      wrappedPrivateKey: crypto.randomBytes(192).toString("base64url"),
      recoverySalt: crypto.randomBytes(16).toString("base64url"),
      recoveryIv: crypto.randomBytes(12).toString("base64url"),
    };
  };
  for (const chatCode of [chatSender, chatRecipient, chatOutsider]) {
    const registration = await request(`/api/vaults/${chatCode}/chat/identity`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(makeChatIdentity()),
    });
    assert.equal(registration.status, 201);
  }
  const senderIdentity = await request(`/api/vaults/${chatSender}/chat/identity`);
  assert.equal((await senderIdentity.json()).registered, true);
  const duplicateIdentity = await request(`/api/vaults/${chatSender}/chat/identity`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(makeChatIdentity()),
  });
  assert.equal(duplicateIdentity.status, 409);
  const invalidChatCode = await makeChatVault();
  const malformedIdentity = makeChatIdentity();
  malformedIdentity.publicKey.agreement.d = "private-material";
  const rejectedPrivateKey = await request(`/api/vaults/${invalidChatCode}/chat/identity`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(malformedIdentity),
  });
  assert.equal(rejectedPrivateKey.status, 400);

  const sentRequest = await request(`/api/vaults/${chatSender}/chat/requests`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ recipientCode: chatRecipient.toLowerCase() }),
  });
  assert.equal(sentRequest.status, 201);
  const chatRequest = await sentRequest.json();
  const incomingRequests = await request(`/api/vaults/${chatRecipient}/chat/requests`);
  assert.deepEqual((await incomingRequests.json()).requests.map((item) => item.senderCode), [chatSender]);
  const accepted = await request(`/api/vaults/${chatRecipient}/chat/requests/${chatRequest.id}/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  assert.equal(accepted.status, 200);
  const conversation = await accepted.json();
  assert.equal(conversation.peerCode, chatSender);
  const encryptedMessage = {
    iv: crypto.randomBytes(12).toString("base64url"),
    ciphertext: crypto.randomBytes(32).toString("base64url"),
    signature: crypto.randomBytes(64).toString("base64url"),
  };
  const sentMessage = await request(
    `/api/vaults/${chatSender}/chat/conversations/${conversation.id}/messages`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(encryptedMessage) },
  );
  assert.equal(sentMessage.status, 201);
  const senderMessages = await request(`/api/vaults/${chatSender}/chat/conversations/${conversation.id}/messages`);
  const messageList = await senderMessages.json();
  assert.equal(messageList.messages.length, 1);
  assert.equal(messageList.messages[0].ciphertext, encryptedMessage.ciphertext);
  assert.equal(messageList.messages[0].content, undefined);
  assert.equal((await request(`/api/vaults/${chatOutsider}/chat/conversations/${conversation.id}/messages`)).status, 404);
  assert.equal((await request(`/api/vaults/${chatRecipient}/chat/conversations`)).status, 200);
  const deletedConversation = await request(
    `/api/vaults/${chatSender}/chat/conversations/${conversation.id}`,
    { method: "DELETE" },
  );
  assert.equal(deletedConversation.status, 200);
  assert.deepEqual((await (await request(`/api/vaults/${chatRecipient}/chat/conversations`)).json()).conversations, []);

  const added = await request(`/api/vaults/${code}/snippets`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title: "Test", content: "Hello" }),
  });
  assert.equal(added.status, 201);
  const snippet = await added.json();
  const list = await request(`/api/vaults/${code.toUpperCase()}/snippets`);
  assert.deepEqual((await list.json()).snippets.map(({ id, title, content }) => ({ id, title, content })), [
    { id: snippet.id, title: "Test", content: "Hello" },
  ]);
  assert.equal((await request("/api/vaults/99999x/snippets")).status, 404);

  const driveRoutes = [
    ["POST", "/api/drive/restore"],
    ["GET", `/api/vaults/${code}/drive/connect`],
    ["GET", `/api/vaults/${code}/drive/status`],
    ["POST", `/api/vaults/${code}/drive/disconnect`],
    ["GET", `/api/vaults/${code}/files`],
    ["GET", `/api/vaults/${code}/files/1/content`],
    ["DELETE", `/api/vaults/${code}/files/1`],
    ["GET", "/api/drive/callback"],
  ];
  for (const [method, url] of driveRoutes) {
    const response = await request(url, { method });
    assert.equal(response.status, 501, `${method} ${url}`);
    assert.deepEqual(await response.json(), { error: "Drive needs Postgres" });
  }

  const invalidMagic = await request(`/api/vaults/${code}/files?name=wrong.png`, {
    method: "POST",
    headers: { "content-type": "image/png" },
    body: Buffer.from("not a PNG"),
  });
  assert.equal(invalidMagic.status, 400);

  const svg = await request(`/api/vaults/${code}/files?name=image.svg`, {
    method: "POST",
    headers: { "content-type": "image/svg+xml" },
    body: Buffer.from("<svg/>"),
  });
  assert.equal(svg.status, 400);

  const oversizedSvg = await request(`/api/vaults/${code}/files?name=large.svg`, {
    method: "POST",
    headers: { "content-type": "image/svg+xml" },
    body: Buffer.alloc(5 * 1024 * 1024),
  });
  assert.equal(oversizedSvg.status, 413);

  const tooLarge = await request(`/api/vaults/${code}/files?name=large.png`, {
    method: "POST",
    headers: { "content-type": "image/png" },
    body: Buffer.concat([Buffer.from("89504e47", "hex"), Buffer.alloc(5 * 1024 * 1024)]),
  });
  assert.equal(tooLarge.status, 413);
});
