const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "clipvault-drive-test-"));
process.env.DB_PATH = path.join(tempDir, "test.db");
delete process.env.DATABASE_URL;
delete process.env.VERCEL;
delete process.env.GOOGLE_CLIENT_ID;
delete process.env.GOOGLE_CLIENT_SECRET;
delete process.env.GOOGLE_REDIRECT_URI;
delete process.env.TOKEN_ENC_KEY;

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
  assert.match(homeText, /function renderFileSkeleton\(\)/);
  assert.match(homeText, /aria-label="Checking Google Drive"/);
  assert.match(homeText, /aria-label="Loading files"/);

  const privacy = await request("/privacy.html");
  assert.equal(privacy.status, 200);
  const privacyText = await privacy.text();
  assert.match(privacyText, /Privacy Policy/);
  assert.match(privacyText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/privacy\.html"/);
  assert.match(privacyText, /drive\.file/);
  assert.match(privacyText, /contact\.mohite@gmail\.com/);
  assert.match(privacyText, /Website analytics/);
  assert.match(privacyText, /vercel\.com\/docs\/analytics\/privacy-policy/);
  assert.match(privacyText, /src="\/_vercel\/insights\/script\.js"/);

  const terms = await request("/terms.html");
  assert.equal(terms.status, 200);
  const termsText = await terms.text();
  assert.match(termsText, /Terms of Service/);
  assert.match(termsText, /rel="canonical" href="https:\/\/www\.clipvault\.lol\/terms\.html"/);
  assert.match(termsText, /five-digit code/);
  assert.match(termsText, /Google Drive/);
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

  const created = await request("/api/vaults", { method: "POST" });
  assert.equal(created.status, 201);
  const { code } = await created.json();
  assert.match(code, /^\d{5}$/);
  const added = await request(`/api/vaults/${code}/snippets`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ title: "Test", content: "Hello" }),
  });
  assert.equal(added.status, 201);
  const snippet = await added.json();
  const list = await request(`/api/vaults/${code}/snippets`);
  assert.deepEqual((await list.json()).snippets.map(({ id, title, content }) => ({ id, title, content })), [
    { id: snippet.id, title: "Test", content: "Hello" },
  ]);

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
