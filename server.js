const express = require("express");
const crypto = require("crypto");
const path = require("path");

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
      await pool.query("ALTER TABLE vaults ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE snippets ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY");
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
    return result.rows;
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

function asyncHandler(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      if (!res.headersSent) {
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

app.get("/api/cron/purge", asyncHandler(async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.get("authorization") !== `Bearer ${secret}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  res.json(await purgeOldVaults());
}));

app.use((error, _req, res, _next) => {
  if (!res.headersSent) res.status(500).json({ error: "Server error" });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`ClipVault running on http://localhost:${PORT}`));
}

module.exports = app;
