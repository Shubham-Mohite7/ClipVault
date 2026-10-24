const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
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
  assert.match(homeText, /<title>ClipVault — Free Online Clipboard/);
  assert.match(homeText, /name="description"/);
  assert.match(homeText, /Save text, images, and PDFs/);
  assert.match(homeText, /no ClipVault login required/);
  assert.match(homeText, /Attachments stay in Google Drive/);
  assert.match(homeText, /\"description\": \"A free online clipboard for saving text snippets and attaching images and PDFs in Google Drive/);
  assert.match(homeText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/"/);
  assert.match(homeText, /property="og:title"/);
  assert.match(homeText, /A simple online clipboard for your snippets/);
  const structuredData = homeText.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(structuredData, "homepage should include WebApplication structured data");
  assert.equal(JSON.parse(structuredData[1])["@type"], "WebApplication");
  assert.match(homeText, /href="\/privacy\.html"/);
  assert.match(homeText, /href="\/terms\.html"/);
  assert.match(homeText, /id="themeToggle"/);
  assert.match(homeText, /clipvault-theme/);
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
  assert.match(homeText, /placeholder="A" aria-label="Code character 1"/);
  assert.match(homeText, /placeholder="0" aria-label="Code character 6"/);
  assert.doesNotMatch(homeText, /Your last used code is filled in/);
  assert.match(homeText, /id="openVault" class="btn small secondary hidden"/);
  assert.match(homeText, /function saveRememberedCode\(value\)/);
  assert.match(homeText, /if \(value && value !== rememberedSuggestion\) enterCode\(value\)/);
  assert.match(homeText, /rememberedSuggestion = candidate/);
  assert.match(homeText, /dismissRememberedSuggestion\(\)/);
  assert.match(homeText, /Remember the last code on this device/);
  assert.doesNotMatch(homeText, /Auto sign-in on this device/);
  const signOutHandler = homeText.slice(
    homeText.indexOf('$("logout").onclick'),
    homeText.indexOf("function setActiveTab"),
  );
  assert.doesNotMatch(signOutHandler, /removeItem\(KEY\)/);
  assert.match(homeText, /id="newCode">ABC-123/);
  assert.match(homeText, /move every file uploaded through this ClipVault vault to Google Drive Trash/);

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
  assert.match(privacyText, /connection remains active so you can retry/);
  assert.match(privacyText, /src="\/_vercel\/insights\/script\.js"/);

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
