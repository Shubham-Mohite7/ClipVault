const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Readable } = require("stream");
const {
  createSignedState,
  decryptRefreshToken,
  encryptRefreshToken,
  encryptionKey,
  verifySignedState,
} = require("./drive-security");
const { ALLOWED_MIME_TYPES, validateUpload } = require("./drive-files");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "clipvault.db");
const DATABASE_URL = process.env.DATABASE_URL;
const databaseMode = DATABASE_URL ? "postgres" : process.env.VERCEL ? "unconfigured" : "sqlite";

let db;
let pool;
let postgresSchemaPromise;

if (databaseMode === "postgres") {
  const { Pool } = require("pg");
  let hostname = "";

  try {
    hostname = new URL(DATABASE_URL).hostname;
  } catch {
    // The pool reports connection-string errors when it attempts to connect.
  }

  if (hostname.startsWith("db.") && hostname.endsWith(".supabase.co")) {
    console.warn("This looks like Supabase's direct connection (IPv6-only). Use the pooler connection string instead.");
    console.warn(`Supabase database hostname: ${hostname}`);
  }

  const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  pool = new Pool({
    connectionString: DATABASE_URL,
    max: 1,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 10000,
    ssl: isLocalhost ? false : { rejectUnauthorized: false },
  });
  pool.on("error", (error) => console.error(error.message));
} else if (databaseMode === "sqlite") {
  const Database = require("better-sqlite3");
  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS vaults (
      code        TEXT PRIMARY KEY CHECK (length(code) = 5),
      created_at  INTEGER NOT NULL,
      last_used   INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS snippets (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      vault_code  TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      title       TEXT NOT NULL,
      content     TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      updated_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_snippets_vault ON snippets(vault_code);
  `);
}

const YEAR = 365 * 24 * 3600 * 1000;
const TWO_DAYS = 2 * 24 * 3600 * 1000;
const ACCESS_TOKEN_CACHE_MARGIN = 2 * 60 * 1000;
const accessTokenCache = new Map();

function databaseNotConfiguredError() {
  const error = new Error("Database not configured");
  error.code = "DATABASE_NOT_CONFIGURED";
  return error;
}

async function ensureDatabase() {
  if (databaseMode === "unconfigured") throw databaseNotConfiguredError();
  if (databaseMode !== "postgres") return;
  if (!postgresSchemaPromise) {
    postgresSchemaPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS vaults (
          code CHAR(5) PRIMARY KEY CHECK (code ~ '^[0-9]{5}$'),
          created_at BIGINT NOT NULL,
          last_used BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS snippets (
          id BIGSERIAL PRIMARY KEY,
          vault_code CHAR(5) NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL
        )
      `);
      await pool.query("CREATE INDEX IF NOT EXISTS idx_snippets_vault ON snippets(vault_code)");
      await pool.query(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT NOT NULL,
          window_start BIGINT NOT NULL,
          count INTEGER NOT NULL,
          PRIMARY KEY (key, window_start)
        )
      `);
      await pool.query("ALTER TABLE vaults ADD COLUMN IF NOT EXISTS drive_refresh_token TEXT");
      await pool.query("ALTER TABLE vaults ADD COLUMN IF NOT EXISTS drive_folder_id TEXT");
      await pool.query("ALTER TABLE vaults ADD COLUMN IF NOT EXISTS drive_email TEXT");
      await pool.query(`
        CREATE TABLE IF NOT EXISTS files (
          id BIGSERIAL PRIMARY KEY,
          vault_code CHAR(5) NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
          drive_file_id TEXT NOT NULL,
          name TEXT NOT NULL,
          mime TEXT NOT NULL,
          size INTEGER NOT NULL,
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query("CREATE INDEX IF NOT EXISTS idx_files_vault ON files(vault_code)");
      await pool.query("ALTER TABLE vaults ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE snippets ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE files ENABLE ROW LEVEL SECURITY");
    })();
  }
  await postgresSchemaPromise;
}

async function createVault() {
  await ensureDatabase();
  for (let attempt = 0; attempt < 50; attempt++) {
    const code = String(crypto.randomInt(0, 100000)).padStart(5, "0");
    const now = Date.now();
    if (databaseMode === "postgres") {
      try {
        await pool.query(
          "INSERT INTO vaults (code, created_at, last_used) VALUES ($1, $2, $3)",
          [code, now, now],
        );
        return code;
      } catch (error) {
        if (error.code === "23505") continue;
        throw error;
      }
    }
    const exists = db.prepare("SELECT 1 FROM vaults WHERE code = ?").get(code);
    if (exists) continue;
    db.prepare("INSERT INTO vaults (code, created_at, last_used) VALUES (?, ?, ?)").run(code, now, now);
    return code;
  }
  throw new Error("No free codes");
}

async function vaultExists(code) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query("SELECT 1 FROM vaults WHERE code = $1", [code]);
    return result.rowCount > 0;
  }
  return Boolean(db.prepare("SELECT 1 FROM vaults WHERE code = ?").get(code));
}

async function touchVault(code) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    await pool.query("UPDATE vaults SET last_used = $1 WHERE code = $2", [Date.now(), code]);
    return;
  }
  db.prepare("UPDATE vaults SET last_used = ? WHERE code = ?").run(Date.now(), code);
}

async function listSnippets(code) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query(
      "SELECT id, title, content, updated_at FROM snippets WHERE vault_code = $1 ORDER BY updated_at DESC",
      [code],
    );
    return result.rows.map((snippet) => ({
      ...snippet,
      id: Number(snippet.id),
      updated_at: Number(snippet.updated_at),
    }));
  }
  return db.prepare(
    "SELECT id, title, content, updated_at FROM snippets WHERE vault_code = ? ORDER BY updated_at DESC",
  ).all(code);
}

async function countSnippets(code) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query("SELECT COUNT(*) AS n FROM snippets WHERE vault_code = $1", [code]);
    return Number(result.rows[0].n);
  }
  return db.prepare("SELECT COUNT(*) AS n FROM snippets WHERE vault_code = ?").get(code).n;
}

async function insertSnippet(code, title, content, now) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query(
      "INSERT INTO snippets (vault_code, title, content, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [code, title, content, now, now],
    );
    return Number(result.rows[0].id);
  }
  const result = db.prepare(
    "INSERT INTO snippets (vault_code, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  ).run(code, title, content, now, now);
  return result.lastInsertRowid;
}

async function updateSnippet(code, id, title, content, now) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query(
      "UPDATE snippets SET title = $1, content = $2, updated_at = $3 WHERE id = $4 AND vault_code = $5",
      [title, content, now, id, code],
    );
    return result.rowCount > 0;
  }
  const result = db.prepare(
    "UPDATE snippets SET title = ?, content = ?, updated_at = ? WHERE id = ? AND vault_code = ?",
  ).run(title, content, now, id, code);
  return result.changes > 0;
}

async function deleteSnippet(code, id) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    await pool.query("DELETE FROM snippets WHERE id = $1 AND vault_code = $2", [id, code]);
    return;
  }
  db.prepare("DELETE FROM snippets WHERE id = ? AND vault_code = ?").run(id, code);
}

async function purgeOldVaults() {
  await ensureDatabase();
  const cutoff = Date.now() - YEAR;
  let vaultsDeleted;
  let rateLimitsDeleted = 0;

  if (databaseMode === "postgres") {
    const vaults = await pool.query("DELETE FROM vaults WHERE last_used < $1", [cutoff]);
    vaultsDeleted = vaults.rowCount;
    const rateLimits = await pool.query("DELETE FROM rate_limits WHERE window_start < $1", [Date.now() - TWO_DAYS]);
    rateLimitsDeleted = rateLimits.rowCount;
  } else {
    const result = db.prepare("DELETE FROM vaults WHERE last_used < ?").run(cutoff);
    vaultsDeleted = result.changes;
  }

  return { vaultsDeleted, rateLimitsDeleted };
}

function driveConfiguration() {
  if (databaseMode !== "postgres") {
    return { error: "Drive needs Postgres" };
  }
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET
      || !process.env.GOOGLE_REDIRECT_URI || !/^[a-f\d]{64}$/i.test(process.env.TOKEN_ENC_KEY || "")) {
    return { error: "Drive not configured" };
  }
  return {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
    encryptionKey: encryptionKey(),
  };
}

function driveError(message, status, code) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function googleError() {
  return driveError("Google Drive error", 502, "GOOGLE_DRIVE_ERROR");
}

async function getDriveVault(code) {
  await ensureDatabase();
  const result = await pool.query(
    "SELECT drive_refresh_token, drive_folder_id, drive_email FROM vaults WHERE code = $1",
    [code],
  );
  return result.rows[0] || null;
}

async function clearDriveVault(code) {
  await pool.query(
    "UPDATE vaults SET drive_refresh_token = NULL, drive_folder_id = NULL, drive_email = NULL WHERE code = $1",
    [code],
  );
  accessTokenCache.delete(code);
}

async function getDriveAccessToken(code, vault) {
  const cached = accessTokenCache.get(code);
  if (cached && cached.expiresAt > Date.now() + ACCESS_TOKEN_CACHE_MARGIN) return cached.token;
  if (!vault?.drive_refresh_token) {
    throw driveError("Drive disconnected. Please reconnect.", 409, "DRIVE_DISCONNECTED");
  }

  const config = driveConfiguration();
  const refreshToken = decryptRefreshToken(vault.drive_refresh_token, config.encryptionKey);
  let response;
  try {
    response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
      }),
    });
  } catch {
    throw googleError();
  }

  let tokens;
  try {
    tokens = await response.json();
  } catch {
    throw googleError();
  }
  if (!response.ok) {
    if (tokens.error === "invalid_grant") {
      await clearDriveVault(code);
      throw driveError("Drive disconnected. Please reconnect.", 409, "DRIVE_DISCONNECTED");
    }
    throw googleError();
  }
  if (typeof tokens.access_token !== "string" || !Number.isFinite(tokens.expires_in)) throw googleError();

  const expiresAt = Date.now() + tokens.expires_in * 1000;
  for (const [cachedCode, value] of accessTokenCache) {
    if (value.expiresAt <= Date.now() + ACCESS_TOKEN_CACHE_MARGIN) accessTokenCache.delete(cachedCode);
  }
  accessTokenCache.set(code, { token: tokens.access_token, expiresAt });
  if (accessTokenCache.size > 1000) accessTokenCache.delete(accessTokenCache.keys().next().value);
  return tokens.access_token;
}

async function googleJson(url, options) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw googleError();
  }
  if (!response.ok) throw googleError();
  try {
    return await response.json();
  } catch {
    throw googleError();
  }
}

function driveAuthorizationHeader(accessToken) {
  return { authorization: `Bearer ${accessToken}` };
}

async function listDriveFiles(code) {
  const result = await pool.query(
    "SELECT id, name, mime, size, created_at FROM files WHERE vault_code = $1 ORDER BY created_at DESC",
    [code],
  );
  return result.rows.map((file) => ({
    ...file,
    id: Number(file.id),
    size: Number(file.size),
    created_at: Number(file.created_at),
  }));
}

async function getDriveFile(code, id) {
  const result = await pool.query(
    "SELECT id, drive_file_id, name, mime, size, created_at FROM files WHERE vault_code = $1 AND id = $2",
    [code, id],
  );
  const file = result.rows[0];
  if (!file) return null;
  return {
    ...file,
    id: Number(file.id),
    size: Number(file.size),
    created_at: Number(file.created_at),
  };
}

async function deleteDriveFileRow(code, id) {
  await pool.query("DELETE FROM files WHERE vault_code = $1 AND id = $2", [code, id]);
}

function buildMultipartBody(file, boundary) {
  return Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`),
    Buffer.from(JSON.stringify({ name: file.name, mimeType: file.mime, parents: [file.folderId] })),
    Buffer.from(`\r\n--${boundary}\r\nContent-Type: ${file.mime}\r\n\r\n`),
    file.body,
    Buffer.from(`\r\n--${boundary}--`),
  ]);
}

async function uploadToDrive(accessToken, folderId, file) {
  const boundary = `clipvault_${crypto.randomBytes(16).toString("hex")}`;
  return googleJson(
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id",
    {
      method: "POST",
      headers: {
        ...driveAuthorizationHeader(accessToken),
        "content-type": `multipart/related; boundary=${boundary}`,
      },
      body: buildMultipartBody({ ...file, folderId }, boundary),
    },
  );
}

function requireDriveBackend(_req, res, next) {
  const config = driveConfiguration();
  if (config.error) return res.status(501).json({ error: config.error });
  next();
}

async function requireDriveConnection(req, res, next) {
  try {
    const vault = await getDriveVault(req.params.code);
    if (!vault?.drive_refresh_token || !vault.drive_folder_id) {
      return res.status(409).json({ error: "Drive disconnected. Please reconnect." });
    }
    req.driveVault = vault;
    next();
  } catch {
    res.status(500).json({ error: "Server error" });
  }
}

function asyncHandler(handler) {
  return async (req, res, next) => {
    try {
      await handler(req, res, next);
    } catch (error) {
      if (!res.headersSent) {
        if (error?.status) return res.status(error.status).json({ error: error.message });
        const message = error?.code === "DATABASE_NOT_CONFIGURED" ? "Database not configured" : "Server error";
        res.status(500).json({ error: message });
      }
    }
  };
}

function limiter({ name, windowMs, max }) {
  const hits = new Map();
  return async (req, res, next) => {
    if (databaseMode === "unconfigured") return next();

    const forwardedFor = req.get("x-forwarded-for");
    const ip = forwardedFor?.split(",")[0].trim() || req.ip;
    const key = `${name}:${ip}`;
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;

    if (databaseMode === "postgres") {
      try {
        await ensureDatabase();
        const result = await pool.query(
          `INSERT INTO rate_limits (key, window_start, count) VALUES ($1, $2, 1)
           ON CONFLICT (key, window_start)
           DO UPDATE SET count = rate_limits.count + 1
           RETURNING count`,
          [key, windowStart],
        );
        if (result.rows[0].count > max) {
          return res.status(429).json({ error: "Too many attempts. Try again soon." });
        }
      } catch (error) {
        console.error(error.message);
      }
      return next();
    }

    const current = hits.get(key);
    const count = current?.windowStart === windowStart ? current.count + 1 : 1;
    hits.set(key, { windowStart, count });
    if (count > max) return res.status(429).json({ error: "Too many attempts. Try again soon." });
    next();
  };
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const createLimit = limiter({ name: "create", windowMs: 60 * 60 * 1000, max: 10 });
const lookupLimit = limiter({ name: "lookup", windowMs: 60 * 1000, max: 20 });
const uploadLimit = limiter({ name: "upload", windowMs: 60 * 60 * 1000, max: 30 });
// Supports lazy thumbnails for a full 50-file vault without changing the 20/min code-lookup limit.
const fileContentLimit = limiter({ name: "file-content", windowMs: 60 * 1000, max: 60 });

async function requireVault(req, res, next) {
  try {
    await ensureDatabase();
    const code = req.params.code;
    if (!/^\d{5}$/.test(code) || !(await vaultExists(code))) {
      return res.status(404).json({ error: "Code not found" });
    }
    await touchVault(code);
    next();
  } catch (error) {
    const message = error?.code === "DATABASE_NOT_CONFIGURED" ? "Database not configured" : "Server error";
    res.status(500).json({ error: message });
  }
}

function validate(body) {
  const title = String(body.title || "").trim().slice(0, 100);
  const content = String(body.content || "");
  if (!content.trim()) return { error: "Text can't be empty" };
  if (content.length > 20000) return { error: "Text is too long (max 20,000 characters)" };
  return { title: title || "Untitled", content };
}

app.get("/healthz", asyncHandler(async (_req, res) => {
  await ensureDatabase();
  if (databaseMode === "postgres") await pool.query("SELECT 1");
  res.json({ ok: true });
}));

app.post("/api/vaults", createLimit, asyncHandler(async (_req, res) => {
  const code = await createVault();
  res.status(201).json({ code });
}));

app.get("/api/vaults/:code/snippets", lookupLimit, requireVault, asyncHandler(async (req, res) => {
  res.json({ snippets: await listSnippets(req.params.code) });
}));

app.post("/api/vaults/:code/snippets", lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const value = validate(req.body);
  if (value.error) return res.status(400).json({ error: value.error });
  if (await countSnippets(req.params.code) >= 200) {
    return res.status(400).json({ error: "Limit of 200 snippets reached" });
  }
  const id = await insertSnippet(req.params.code, value.title, value.content, Date.now());
  res.status(201).json({ id });
}));

app.put("/api/vaults/:code/snippets/:id", lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const value = validate(req.body);
  if (value.error) return res.status(400).json({ error: value.error });
  const updated = await updateSnippet(req.params.code, Number(req.params.id), value.title, value.content, Date.now());
  if (!updated) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
}));

app.delete("/api/vaults/:code/snippets/:id", lookupLimit, requireVault, asyncHandler(async (req, res) => {
  await deleteSnippet(req.params.code, Number(req.params.id));
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/drive/connect", requireDriveBackend, lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const vault = await getDriveVault(req.params.code);
  if (vault?.drive_refresh_token) {
    return res.status(409).json({ error: "Google Drive is already connected" });
  }
  const config = driveConfiguration();
  const state = createSignedState(req.params.code, config.encryptionKey);
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: "code",
    scope: "https://www.googleapis.com/auth/drive.file email",
    access_type: "offline",
    prompt: "consent",
    state,
  }).toString();
  res.json({ url: url.toString() });
}));

app.get("/api/drive/callback", requireDriveBackend, asyncHandler(async (req, res) => {
  try {
    if (typeof req.query.code !== "string" || typeof req.query.state !== "string" || req.query.error) {
      throw new Error("OAuth callback failed");
    }
    const config = driveConfiguration();
    const state = verifySignedState(req.query.state, config.encryptionKey);
    if (!(await vaultExists(state.code))) throw new Error("Vault not found");

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: req.query.code,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectUri,
        grant_type: "authorization_code",
      }),
    });
    let tokens;
    try {
      tokens = await tokenResponse.json();
    } catch {
      throw googleError();
    }
    if (!tokenResponse.ok || typeof tokens.refresh_token !== "string" || !tokens.refresh_token
        || typeof tokens.access_token !== "string") {
      throw googleError();
    }

    const user = await googleJson("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: driveAuthorizationHeader(tokens.access_token),
    });
    if (typeof user.email !== "string" || !user.email) throw googleError();
    const folder = await googleJson("https://www.googleapis.com/drive/v3/files?fields=id", {
      method: "POST",
      headers: {
        ...driveAuthorizationHeader(tokens.access_token),
        "content-type": "application/json",
      },
      body: JSON.stringify({ name: "ClipVault", mimeType: "application/vnd.google-apps.folder" }),
    });
    if (typeof folder.id !== "string" || !folder.id) throw googleError();

    await pool.query(
      "UPDATE vaults SET drive_refresh_token = $1, drive_folder_id = $2, drive_email = $3 WHERE code = $4",
      [encryptRefreshToken(tokens.refresh_token, config.encryptionKey), folder.id, user.email, state.code],
    );
    accessTokenCache.delete(state.code);
    res.redirect("/?drive=connected");
  } catch {
    res.redirect("/?drive=error");
  }
}));

app.get("/api/vaults/:code/drive/status", requireDriveBackend, lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const vault = await getDriveVault(req.params.code);
  const connected = Boolean(vault?.drive_refresh_token && vault.drive_folder_id);
  res.json({ connected, email: connected ? vault.drive_email : null });
}));

app.post("/api/vaults/:code/drive/disconnect", requireDriveBackend, lookupLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  try {
    const config = driveConfiguration();
    const refreshToken = decryptRefreshToken(req.driveVault.drive_refresh_token, config.encryptionKey);
    await fetch("https://oauth2.googleapis.com/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshToken }),
    });
  } catch {
    // Revocation is best-effort; local access must still be removed.
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "UPDATE vaults SET drive_refresh_token = NULL, drive_folder_id = NULL, drive_email = NULL WHERE code = $1",
      [req.params.code],
    );
    await client.query("DELETE FROM files WHERE vault_code = $1", [req.params.code]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  accessTokenCache.delete(req.params.code);
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/files", requireDriveBackend, lookupLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  res.json({ files: await listDriveFiles(req.params.code) });
}));

app.post(
  "/api/vaults/:code/files",
  express.raw({ type: [...ALLOWED_MIME_TYPES], limit: "4mb" }),
  express.raw({ type: () => true, limit: "4mb" }),
  asyncHandler(async (req, _res, next) => {
    const mime = (req.get("content-type") || "").split(";")[0].trim().toLowerCase();
    req.uploadFile = validateUpload(mime, req.body, req.query.name);
    next();
  }),
  requireDriveBackend,
  uploadLimit,
  lookupLimit,
  requireVault,
  requireDriveConnection,
  asyncHandler(async (req, res) => {
    const accessToken = await getDriveAccessToken(req.params.code, req.driveVault);
    const client = await pool.connect();
    let driveFileId;
    let transactionStarted = false;
    try {
      await client.query("BEGIN");
      transactionStarted = true;
      await client.query("SELECT code FROM vaults WHERE code = $1 FOR UPDATE", [req.params.code]);
      const count = await client.query("SELECT COUNT(*) AS n FROM files WHERE vault_code = $1", [req.params.code]);
      if (Number(count.rows[0].n) >= 50) {
        await client.query("ROLLBACK");
        transactionStarted = false;
        return res.status(400).json({ error: "Limit of 50 files reached" });
      }

      const uploaded = await uploadToDrive(accessToken, req.driveVault.drive_folder_id, req.uploadFile);
      if (typeof uploaded.id !== "string" || !uploaded.id) throw googleError();
      driveFileId = uploaded.id;
      const inserted = await client.query(
        `INSERT INTO files (vault_code, drive_file_id, name, mime, size, created_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [req.params.code, driveFileId, req.uploadFile.name, req.uploadFile.mime, req.uploadFile.size, Date.now()],
      );
      await client.query("COMMIT");
      transactionStarted = false;
      res.status(201).json({ id: Number(inserted.rows[0].id) });
    } catch (error) {
      if (transactionStarted) await client.query("ROLLBACK");
      if (driveFileId) {
        try {
          await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(driveFileId)}`, {
            method: "PATCH",
            headers: { ...driveAuthorizationHeader(accessToken), "content-type": "application/json" },
            body: JSON.stringify({ trashed: true }),
          });
        } catch {}
      }
      throw error;
    } finally {
      client.release();
    }
  }),
);

app.get("/api/vaults/:code/files/:id/content", requireDriveBackend, fileContentLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: "Not found" });
  const file = await getDriveFile(req.params.code, req.params.id);
  if (!file) return res.status(404).json({ error: "Not found" });
  const accessToken = await getDriveAccessToken(req.params.code, req.driveVault);
  let response;
  try {
    response = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.drive_file_id)}?alt=media`,
      { headers: driveAuthorizationHeader(accessToken) },
    );
  } catch {
    throw googleError();
  }
  if (!response.ok || !response.body) throw googleError();

  const dispositionType = req.query.download === "1" ? "attachment" : "inline";
  const fallbackName = file.name.replace(/[^\x20-\x7e]|["\\]/g, "_");
  const encodedFilename = encodeURIComponent(file.name).replace(/['()*]/g, (character) => (
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  ));
  res.set({
    "Content-Type": file.mime,
    "X-Content-Type-Options": "nosniff",
    "Content-Disposition": `${dispositionType}; filename="${fallbackName}"; filename*=UTF-8''${encodedFilename}`,
    "Cache-Control": "private, no-store",
  });
  Readable.fromWeb(response.body).on("error", () => res.destroy()).pipe(res);
}));

app.delete("/api/vaults/:code/files/:id", requireDriveBackend, lookupLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: "Not found" });
  const file = await getDriveFile(req.params.code, req.params.id);
  if (!file) return res.status(404).json({ error: "Not found" });
  const accessToken = await getDriveAccessToken(req.params.code, req.driveVault);
  let response;
  try {
    response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.drive_file_id)}`, {
      method: "PATCH",
      headers: { ...driveAuthorizationHeader(accessToken), "content-type": "application/json" },
      body: JSON.stringify({ trashed: true }),
    });
  } catch {
    throw googleError();
  }
  if (!response.ok && response.status !== 404) throw googleError();
  await deleteDriveFileRow(req.params.code, req.params.id);
  res.json({ ok: true });
}));

app.get("/api/cron/purge", asyncHandler(async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.get("authorization") !== `Bearer ${secret}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json(await purgeOldVaults());
}));

app.use((error, req, res, _next) => {
  if (res.headersSent) return;
  if (error?.type === "entity.too.large" && /^\/api\/vaults\/\d{5}\/files$/.test(req.path)) {
    return res.status(413).json({ error: "File exceeds 4 MB" });
  }
  res.status(500).json({ error: "Server error" });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`ClipVault running on http://localhost:${PORT}`));
}

module.exports = app;
