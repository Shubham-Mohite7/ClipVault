const express = require("express");
const crypto = require("crypto");
const QRCode = require("qrcode");
const path = require("path");
const { Readable } = require("stream");
const {
  createSignedState,
  decryptRefreshToken,
  encryptRefreshToken,
  encryptionKey,
  verifySignedState,
} = require("./drive-security");
const { ALLOWED_MIME_TYPES, trashTrackedFiles, validateUpload } = require("./drive-files");
const { createVaultCode, isValidVaultCode, normalizeVaultCode } = require("./vault-codes");
const { consumeOAuthReturnTicket, issueOAuthReturnTicket } = require("./oauth-return");

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "clipvault.db");
const DATABASE_URL = process.env.DATABASE_URL;
const databaseMode = DATABASE_URL ? "postgres" : process.env.VERCEL ? "unconfigured" : "sqlite";
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL
  || (process.env.VERCEL ? "https://www.clipvault.lol" : "");

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
      code        TEXT PRIMARY KEY CHECK (
        (length(code) = 5 AND code NOT GLOB '*[^0-9]*')
        OR (length(code) = 7 AND substr(code, 4, 1) = '-'
            AND substr(code, 1, 3) NOT GLOB '*[^a-z]*'
            AND substr(code, 5, 3) NOT GLOB '*[^0-9]*')
      ),
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
    CREATE TABLE IF NOT EXISTS chat_identities (
      vault_code TEXT PRIMARY KEY REFERENCES vaults(code) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      wrapped_private_key TEXT NOT NULL,
      recovery_salt TEXT NOT NULL,
      recovery_iv TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS chat_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      recipient_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected')),
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS chat_invites (
      token_hash TEXT PRIMARY KEY,
      sender_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_chat_invites_expiry ON chat_invites(expires_at);
    CREATE INDEX IF NOT EXISTS idx_chat_requests_recipient ON chat_requests(recipient_code, status, created_at);
    CREATE TABLE IF NOT EXISTS chat_conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code_a TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      code_b TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      UNIQUE (code_a, code_b),
      CHECK (code_a < code_b)
    );
    CREATE INDEX IF NOT EXISTS idx_chat_conversations_participants ON chat_conversations(code_a, code_b);
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
      sender_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
      iv TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id, id);
  `);
  const vaultSchema = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'vaults'").get().sql;
  if (!vaultSchema.includes("GLOB")) {
    db.pragma("foreign_keys = OFF");
    try {
      db.exec(`
        BEGIN;
        CREATE TABLE vaults_new (
          code TEXT PRIMARY KEY CHECK (
            (length(code) = 5 AND code NOT GLOB '*[^0-9]*')
            OR (length(code) = 7 AND substr(code, 4, 1) = '-'
                AND substr(code, 1, 3) NOT GLOB '*[^a-z]*'
                AND substr(code, 5, 3) NOT GLOB '*[^0-9]*')
          ),
          created_at INTEGER NOT NULL,
          last_used INTEGER NOT NULL,
          has_added_snippet INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO vaults_new (code, created_at, last_used)
          SELECT code, created_at, last_used FROM vaults;
        DROP TABLE vaults;
        ALTER TABLE vaults_new RENAME TO vaults;
        COMMIT;
      `);
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    } finally {
      db.pragma("foreign_keys = ON");
    }
    if (db.pragma("foreign_key_check").length) {
      throw new Error("SQLite vault-code migration left invalid references");
    }
  }
  if (!db.pragma("table_info(vaults)").some((column) => column.name === "has_added_snippet")) {
    db.exec("ALTER TABLE vaults ADD COLUMN has_added_snippet INTEGER NOT NULL DEFAULT 0");
  }
  db.exec(`
    UPDATE vaults SET has_added_snippet = 1
    WHERE EXISTS (SELECT 1 FROM snippets WHERE snippets.vault_code = vaults.code)
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
          code TEXT PRIMARY KEY CHECK (code ~ '^([0-9]{5}|[a-z]{3}-[0-9]{3})$'),
          created_at BIGINT NOT NULL,
          last_used BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS snippets (
          id BIGSERIAL PRIMARY KEY,
          vault_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          updated_at BIGINT NOT NULL
        )
      `);
      await pool.query("ALTER TABLE vaults ADD COLUMN IF NOT EXISTS has_added_snippet BOOLEAN NOT NULL DEFAULT FALSE");
      await pool.query(`
        UPDATE vaults SET has_added_snippet = TRUE
        WHERE EXISTS (SELECT 1 FROM snippets WHERE snippets.vault_code = vaults.code)
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
          vault_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
          drive_file_id TEXT NOT NULL,
          name TEXT NOT NULL,
          mime TEXT NOT NULL,
          size INTEGER NOT NULL,
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS oauth_return_tickets (
          ticket_hash TEXT PRIMARY KEY,
          vault_code TEXT NOT NULL REFERENCES vaults(code) ON DELETE CASCADE,
          remember BOOLEAN NOT NULL,
          expires_at BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_identities (
          vault_code TEXT PRIMARY KEY,
          public_key TEXT NOT NULL,
          wrapped_private_key TEXT NOT NULL,
          recovery_salt TEXT NOT NULL,
          recovery_iv TEXT NOT NULL,
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_requests (
          id BIGSERIAL PRIMARY KEY,
          sender_code TEXT NOT NULL,
          recipient_code TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected')),
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_invites (
          token_hash TEXT PRIMARY KEY,
          sender_code TEXT NOT NULL,
          expires_at BIGINT NOT NULL,
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query("CREATE INDEX IF NOT EXISTS idx_chat_invites_expiry ON chat_invites(expires_at)");
      await pool.query("CREATE INDEX IF NOT EXISTS idx_chat_requests_recipient ON chat_requests(recipient_code, status, created_at)");
      await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_conversations (
          id BIGSERIAL PRIMARY KEY,
          code_a TEXT NOT NULL,
          code_b TEXT NOT NULL,
          created_at BIGINT NOT NULL,
          UNIQUE (code_a, code_b),
          CHECK (code_a < code_b)
        )
      `);
      await pool.query("CREATE INDEX IF NOT EXISTS idx_chat_conversations_participants ON chat_conversations(code_a, code_b)");
      await pool.query(`
        CREATE TABLE IF NOT EXISTS chat_messages (
          id BIGSERIAL PRIMARY KEY,
          conversation_id BIGINT NOT NULL,
          sender_code TEXT NOT NULL,
          iv TEXT NOT NULL,
          ciphertext TEXT NOT NULL,
          signature TEXT NOT NULL,
          created_at BIGINT NOT NULL
        )
      `);
      await pool.query("CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id, id)");
      await pool.query("CREATE INDEX IF NOT EXISTS idx_oauth_return_tickets_expiry ON oauth_return_tickets(expires_at)");
      await pool.query("CREATE INDEX IF NOT EXISTS idx_files_vault ON files(vault_code)");
      await pool.query("ALTER TABLE snippets DROP CONSTRAINT IF EXISTS snippets_vault_code_fkey");
      await pool.query("ALTER TABLE files DROP CONSTRAINT IF EXISTS files_vault_code_fkey");
      await pool.query("ALTER TABLE chat_identities DROP CONSTRAINT IF EXISTS chat_identities_vault_code_fkey");
      await pool.query("ALTER TABLE chat_requests DROP CONSTRAINT IF EXISTS chat_requests_sender_code_fkey");
      await pool.query("ALTER TABLE chat_requests DROP CONSTRAINT IF EXISTS chat_requests_recipient_code_fkey");
      await pool.query("ALTER TABLE chat_conversations DROP CONSTRAINT IF EXISTS chat_conversations_code_a_fkey");
      await pool.query("ALTER TABLE chat_conversations DROP CONSTRAINT IF EXISTS chat_conversations_code_b_fkey");
      await pool.query("ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_conversation_id_fkey");
      await pool.query("ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS chat_messages_sender_code_fkey");
      await pool.query("ALTER TABLE vaults DROP CONSTRAINT IF EXISTS vaults_code_check");
      await pool.query("ALTER TABLE vaults ALTER COLUMN code TYPE TEXT USING rtrim(code)");
      await pool.query("ALTER TABLE snippets ALTER COLUMN vault_code TYPE TEXT USING rtrim(vault_code)");
      await pool.query("ALTER TABLE files ALTER COLUMN vault_code TYPE TEXT USING rtrim(vault_code)");
      await pool.query(
        "ALTER TABLE vaults ADD CONSTRAINT vaults_code_check CHECK (code ~ '^([0-9]{5}|[a-z]{3}-[0-9]{3})$')",
      );
      await pool.query(
        "ALTER TABLE snippets ADD CONSTRAINT snippets_vault_code_fkey FOREIGN KEY (vault_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE files ADD CONSTRAINT files_vault_code_fkey FOREIGN KEY (vault_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_identities ADD CONSTRAINT chat_identities_vault_code_fkey FOREIGN KEY (vault_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_requests ADD CONSTRAINT chat_requests_sender_code_fkey FOREIGN KEY (sender_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_requests ADD CONSTRAINT chat_requests_recipient_code_fkey FOREIGN KEY (recipient_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_conversations ADD CONSTRAINT chat_conversations_code_a_fkey FOREIGN KEY (code_a) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_conversations ADD CONSTRAINT chat_conversations_code_b_fkey FOREIGN KEY (code_b) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_messages ADD CONSTRAINT chat_messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE",
      );
      await pool.query(
        "ALTER TABLE chat_messages ADD CONSTRAINT chat_messages_sender_code_fkey FOREIGN KEY (sender_code) REFERENCES vaults(code) ON DELETE CASCADE",
      );
      await pool.query("ALTER TABLE vaults ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE snippets ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE files ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE oauth_return_tickets ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE chat_identities ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE chat_requests ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE chat_conversations ENABLE ROW LEVEL SECURITY");
      await pool.query("ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY");
    })();
  }
  await postgresSchemaPromise;
}

async function createVault() {
  await ensureDatabase();
  for (let attempt = 0; attempt < 50; attempt++) {
    const code = normalizeVaultCode(createVaultCode());
    const now = Date.now();
    if (databaseMode === "postgres") {
      try {
        await pool.query(
          "INSERT INTO vaults (code, created_at, last_used) VALUES ($1, $2, $3)",
          [code, now, now],
        );
        return code.toUpperCase();
      } catch (error) {
        if (error.code === "23505") continue;
        throw error;
      }
    }
    const exists = db.prepare("SELECT 1 FROM vaults WHERE code = ?").get(code);
    if (exists) continue;
    db.prepare("INSERT INTO vaults (code, created_at, last_used) VALUES (?, ?, ?)").run(code, now, now);
    return code.toUpperCase();
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
      `WITH inserted AS (
        INSERT INTO snippets (vault_code, title, content, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5) RETURNING id
      ), marked AS (
        UPDATE vaults SET has_added_snippet = TRUE WHERE code = $1
      )
      SELECT id FROM inserted`,
      [code, title, content, now, now],
    );
    return Number(result.rows[0].id);
  }
  return db.transaction(() => {
    const result = db.prepare(
      "INSERT INTO snippets (vault_code, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run(code, title, content, now, now);
    db.prepare("UPDATE vaults SET has_added_snippet = 1 WHERE code = ?").run(code);
    return result.lastInsertRowid;
  })();
}

async function vaultHasEverAddedSnippet(code) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query("SELECT has_added_snippet FROM vaults WHERE code = $1", [code]);
    return Boolean(result.rows[0]?.has_added_snippet);
  }
  return Boolean(db.prepare("SELECT has_added_snippet FROM vaults WHERE code = ?").get(code)?.has_added_snippet);
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

async function getChatIdentity(code) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT public_key, wrapped_private_key, recovery_salt, recovery_iv FROM chat_identities WHERE vault_code = $1",
      [code],
    )
    : { rows: [db.prepare(
      "SELECT public_key, wrapped_private_key, recovery_salt, recovery_iv FROM chat_identities WHERE vault_code = ?",
    ).get(code)].filter(Boolean) };
  return result.rows[0] || null;
}

function chatPeerId(identity) {
  if (!identity?.public_key) return "";
  return crypto.createHash("sha256").update(identity.public_key).digest("base64url").slice(0, 22);
}

async function createChatInvite(senderCode) {
  await ensureDatabase();
  const now = Date.now();
  if (databaseMode === "postgres") await pool.query("DELETE FROM chat_invites WHERE expires_at <= $1", [now]);
  else db.prepare("DELETE FROM chat_invites WHERE expires_at <= ?").run(now);
  if (databaseMode === "postgres") await pool.query("DELETE FROM chat_invites WHERE sender_code = $1", [senderCode]);
  else db.prepare("DELETE FROM chat_invites WHERE sender_code = ?").run(senderCode);
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const expiresAt = now + 24 * 60 * 60 * 1000;
  if (databaseMode === "postgres") {
    await pool.query("INSERT INTO chat_invites (token_hash, sender_code, expires_at, created_at) VALUES ($1, $2, $3, $4)", [tokenHash, senderCode, expiresAt, now]);
  } else {
    db.prepare("INSERT INTO chat_invites (token_hash, sender_code, expires_at, created_at) VALUES (?, ?, ?, ?)").run(tokenHash, senderCode, expiresAt, now);
  }
  return { token, expiresAt };
}

async function consumeChatInvite(token, recipientCode) {
  await ensureDatabase();
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const now = Date.now();
  const invite = databaseMode === "postgres"
    ? await pool.query("SELECT sender_code FROM chat_invites WHERE token_hash = $1 AND expires_at > $2", [tokenHash, now])
    : { rows: [db.prepare("SELECT sender_code FROM chat_invites WHERE token_hash = ? AND expires_at > ?").get(tokenHash, now)].filter(Boolean) };
  if (!invite.rows[0]) return { error: "This chat QR has expired. Ask your friend for a new one." };
  const senderCode = invite.rows[0].sender_code;
  if (senderCode === recipientCode) return { error: "You cannot send a chat request to yourself." };
  if (!(await getChatIdentity(senderCode))) return { error: "This chat invitation is no longer available." };
  if (await chatConversationExists(recipientCode, senderCode)) return { error: "You already have a chat with this contact." };
  return { request: await createChatRequest(recipientCode, senderCode) };
}

async function createChatIdentity(code, value) {
  await ensureDatabase();
  const values = [code, JSON.stringify(value.publicKey), value.wrappedPrivateKey, value.recoverySalt, value.recoveryIv, Date.now()];
  if (databaseMode === "postgres") {
    const result = await pool.query(
      `INSERT INTO chat_identities
        (vault_code, public_key, wrapped_private_key, recovery_salt, recovery_iv, created_at)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (vault_code) DO NOTHING RETURNING vault_code`,
      values,
    );
    return result.rowCount > 0;
  }
  const result = db.prepare(
    `INSERT OR IGNORE INTO chat_identities
      (vault_code, public_key, wrapped_private_key, recovery_salt, recovery_iv, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(...values);
  return result.changes > 0;
}

async function replaceChatIdentity(code, value) {
  await ensureDatabase();
  const values = [JSON.stringify(value.publicKey), value.wrappedPrivateKey, value.recoverySalt, value.recoveryIv, Date.now(), code];
  if (databaseMode === "postgres") {
    await pool.query(
      `UPDATE chat_identities
       SET public_key = $1, wrapped_private_key = $2, recovery_salt = $3, recovery_iv = $4, created_at = $5
       WHERE vault_code = $6`,
      values,
    );
    return;
  }
  db.prepare(
    `UPDATE chat_identities
     SET public_key = ?, wrapped_private_key = ?, recovery_salt = ?, recovery_iv = ?, created_at = ?
     WHERE vault_code = ?`,
  ).run(...values);
}

async function createChatRequest(senderCode, recipientCode) {
  await ensureDatabase();
  const existing = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id FROM chat_requests WHERE sender_code = $1 AND recipient_code = $2 AND status = 'pending' ORDER BY id DESC LIMIT 1",
      [senderCode, recipientCode],
    )
    : { rows: db.prepare(
      "SELECT id FROM chat_requests WHERE sender_code = ? AND recipient_code = ? AND status = 'pending' ORDER BY id DESC LIMIT 1",
    ).all(senderCode, recipientCode) };
  if (existing.rows[0]) return { id: String(existing.rows[0].id), existing: true };
  const now = Date.now();
  const created = databaseMode === "postgres"
    ? await pool.query(
      "INSERT INTO chat_requests (sender_code, recipient_code, status, created_at) VALUES ($1, $2, 'pending', $3) RETURNING id",
      [senderCode, recipientCode, now],
    )
    : { rows: [{ id: db.prepare(
      "INSERT INTO chat_requests (sender_code, recipient_code, status, created_at) VALUES (?, ?, 'pending', ?)",
    ).run(senderCode, recipientCode, now).lastInsertRowid }] };
  return { id: String(created.rows[0].id), existing: false };
}

async function listChatRequests(recipientCode) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id, sender_code, created_at FROM chat_requests WHERE recipient_code = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 50",
      [recipientCode],
    )
    : { rows: db.prepare(
      "SELECT id, sender_code, created_at FROM chat_requests WHERE recipient_code = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 50",
    ).all(recipientCode) };
  return Promise.all(result.rows.map(async (request) => {
    const identity = await getChatIdentity(request.sender_code);
    return { id: String(request.id), peerId: chatPeerId(identity), createdAt: Number(request.created_at) };
  }));
}

async function listSentChatRequests(senderCode) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id, recipient_code, status, created_at FROM chat_requests WHERE sender_code = $1 ORDER BY created_at DESC LIMIT 50",
      [senderCode],
    )
    : { rows: db.prepare(
      "SELECT id, recipient_code, status, created_at FROM chat_requests WHERE sender_code = ? ORDER BY created_at DESC LIMIT 50",
    ).all(senderCode) };
  return Promise.all(result.rows.map(async (request) => {
    const identity = await getChatIdentity(request.recipient_code);
    return { id: String(request.id), peerId: chatPeerId(identity), status: request.status, createdAt: Number(request.created_at) };
  }));
}

async function acceptChatRequest(recipientCode, requestId) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const request = await client.query(
        "SELECT sender_code FROM chat_requests WHERE id = $1 AND recipient_code = $2 AND status = 'pending' FOR UPDATE",
        [requestId, recipientCode],
      );
      if (!request.rowCount) {
        await client.query("ROLLBACK");
        return null;
      }
      const senderCode = request.rows[0].sender_code;
      const [codeA, codeB] = [senderCode, recipientCode].sort();
      await client.query("UPDATE chat_requests SET status = 'accepted' WHERE id = $1", [requestId]);
      const conversation = await client.query(
        `INSERT INTO chat_conversations (code_a, code_b, created_at) VALUES ($1, $2, $3)
         ON CONFLICT (code_a, code_b) DO UPDATE SET code_a = EXCLUDED.code_a RETURNING id`,
        [codeA, codeB, Date.now()],
      );
      await client.query("COMMIT");
      return { id: String(conversation.rows[0].id), peerId: chatPeerId(await getChatIdentity(senderCode)) };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  const accept = db.transaction(() => {
    const request = db.prepare(
      "SELECT sender_code FROM chat_requests WHERE id = ? AND recipient_code = ? AND status = 'pending'",
    ).get(requestId, recipientCode);
    if (!request) return null;
    const [codeA, codeB] = [request.sender_code, recipientCode].sort();
    db.prepare("UPDATE chat_requests SET status = 'accepted' WHERE id = ?").run(requestId);
    db.prepare(
      "INSERT OR IGNORE INTO chat_conversations (code_a, code_b, created_at) VALUES (?, ?, ?)",
    ).run(codeA, codeB, Date.now());
    const conversation = db.prepare(
      "SELECT id FROM chat_conversations WHERE code_a = ? AND code_b = ?",
    ).get(codeA, codeB);
    return { id: String(conversation.id), peerCode: request.sender_code };
  });
  const accepted = accept();
  return accepted ? { id: accepted.id, peerId: chatPeerId(await getChatIdentity(accepted.peerCode)) } : null;
}

async function rejectChatRequest(recipientCode, requestId) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query(
      "UPDATE chat_requests SET status = 'rejected' WHERE id = $1 AND recipient_code = $2 AND status = 'pending'",
      [requestId, recipientCode],
    );
    return result.rowCount > 0;
  }
  const result = db.prepare(
    "UPDATE chat_requests SET status = 'rejected' WHERE id = ? AND recipient_code = ? AND status = 'pending'",
  ).run(requestId, recipientCode);
  return result.changes > 0;
}

async function listChatConversations(code) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id, code_a, code_b, created_at FROM chat_conversations WHERE code_a = $1 OR code_b = $1 ORDER BY id DESC LIMIT 100",
      [code],
    )
    : { rows: db.prepare(
      "SELECT id, code_a, code_b, created_at FROM chat_conversations WHERE code_a = ? OR code_b = ? ORDER BY id DESC LIMIT 100",
    ).all(code, code) };
  const conversations = [];
  for (const conversation of result.rows) {
    const peerCode = conversation.code_a === code ? conversation.code_b : conversation.code_a;
    const identity = await getChatIdentity(peerCode);
    if (!identity) continue;
    conversations.push({
      id: String(conversation.id),
      peerId: chatPeerId(identity),
      peerPublicKey: JSON.parse(identity.public_key),
      createdAt: Number(conversation.created_at),
    });
  }
  return conversations;
}

async function getChatConversation(code, conversationId) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id, code_a, code_b FROM chat_conversations WHERE id = $1 AND (code_a = $2 OR code_b = $2)",
      [conversationId, code],
    )
    : { rows: [db.prepare(
      "SELECT id, code_a, code_b FROM chat_conversations WHERE id = ? AND (code_a = ? OR code_b = ?)",
    ).get(conversationId, code, code)].filter(Boolean) };
  return result.rows[0] || null;
}

async function chatConversationExists(code, peerCode) {
  await ensureDatabase();
  const [codeA, codeB] = [code, peerCode].sort();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT 1 FROM chat_conversations WHERE code_a = $1 AND code_b = $2",
      [codeA, codeB],
    )
    : { rows: [db.prepare(
      "SELECT 1 FROM chat_conversations WHERE code_a = ? AND code_b = ?",
    ).get(codeA, codeB)].filter(Boolean) };
  return result.rows.length > 0;
}

async function listChatMessages(conversationId, afterId) {
  await ensureDatabase();
  const result = databaseMode === "postgres"
    ? await pool.query(
      "SELECT id, sender_code, iv, ciphertext, signature, created_at FROM chat_messages WHERE conversation_id = $1 AND id > $2 ORDER BY id ASC LIMIT 100",
      [conversationId, afterId],
    )
    : { rows: db.prepare(
      "SELECT id, sender_code, iv, ciphertext, signature, created_at FROM chat_messages WHERE conversation_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
    ).all(conversationId, afterId) };
  const senderCodes = [...new Set(result.rows.map((message) => message.sender_code))];
  const senderIdentities = new Map(await Promise.all(senderCodes.map(async (code) => [code, await getChatIdentity(code)])));
  return result.rows.map((message) => ({
    id: String(message.id),
    senderId: chatPeerId(senderIdentities.get(message.sender_code)),
    iv: message.iv,
    ciphertext: message.ciphertext,
    signature: message.signature,
    createdAt: Number(message.created_at),
  }));
}

async function insertChatMessage(conversationId, senderCode, iv, ciphertext, signature) {
  await ensureDatabase();
  const values = [conversationId, senderCode, iv, ciphertext, signature, Date.now()];
  const result = databaseMode === "postgres"
    ? await pool.query(
      "INSERT INTO chat_messages (conversation_id, sender_code, iv, ciphertext, signature, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at",
      values,
    )
    : { rows: [db.prepare(
      "INSERT INTO chat_messages (conversation_id, sender_code, iv, ciphertext, signature, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(...values)].map((inserted) => ({ id: inserted.lastInsertRowid, created_at: values[5] })) };
  return { id: String(result.rows[0].id), createdAt: Number(result.rows[0].created_at) };
}

async function deleteChatConversation(code, conversationId) {
  await ensureDatabase();
  if (databaseMode === "postgres") {
    const result = await pool.query(
      "DELETE FROM chat_conversations WHERE id = $1 AND (code_a = $2 OR code_b = $2)",
      [conversationId, code],
    );
    return result.rowCount > 0;
  }
  const result = db.prepare(
    "DELETE FROM chat_conversations WHERE id = ? AND (code_a = ? OR code_b = ?)",
  ).run(conversationId, code, code);
  return result.changes > 0;
}

async function purgeOldVaults() {
  await ensureDatabase();
  const cutoff = Date.now() - YEAR;
  let vaultsDeleted;
  let rateLimitsDeleted = 0;
  let oauthReturnTicketsDeleted = 0;

  if (databaseMode === "postgres") {
    const vaults = await pool.query("DELETE FROM vaults WHERE last_used < $1", [cutoff]);
    vaultsDeleted = vaults.rowCount;
    const rateLimits = await pool.query("DELETE FROM rate_limits WHERE window_start < $1", [Date.now() - TWO_DAYS]);
    rateLimitsDeleted = rateLimits.rowCount;
    const oauthTickets = await pool.query("DELETE FROM oauth_return_tickets WHERE expires_at < $1", [Date.now()]);
    oauthReturnTicketsDeleted = oauthTickets.rowCount;
  } else {
    const result = db.prepare("DELETE FROM vaults WHERE last_used < ?").run(cutoff);
    vaultsDeleted = result.changes;
  }

  return { vaultsDeleted, rateLimitsDeleted, oauthReturnTicketsDeleted };
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
const codeCheckLimit = limiter({ name: "code-check", windowMs: 60 * 1000, max: 20 });
const oauthReturnLimit = limiter({ name: "oauth-return", windowMs: 60 * 1000, max: 10 });
const uploadLimit = limiter({ name: "upload", windowMs: 60 * 60 * 1000, max: 30 });
// Supports lazy thumbnails for a full 50-file vault without changing the 20/min code-lookup limit.
const fileContentLimit = limiter({ name: "file-content", windowMs: 60 * 1000, max: 60 });
const chatReadLimit = limiter({ name: "chat-read", windowMs: 60 * 1000, max: 120 });
const chatMessageReadLimit = limiter({ name: "chat-message-read", windowMs: 60 * 1000, max: 240 });
const chatWriteLimit = limiter({ name: "chat-write", windowMs: 60 * 1000, max: 30 });
const chatTypingLimit = limiter({ name: "chat-typing", windowMs: 60 * 1000, max: 60 });
const chatTypingStates = new Map();

async function requireVault(req, res, next) {
  try {
    await ensureDatabase();
    const code = normalizeVaultCode(req.params.code);
    if (!isValidVaultCode(code) || !(await vaultExists(code))) {
      return res.status(404).json({ error: "Code not found" });
    }
    req.params.code = code;
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

function isPublicChatKey(key) {
  return key?.kty === "EC" && key.crv === "P-256"
    && /^[A-Za-z0-9_-]{43}$/.test(key.x || "")
    && /^[A-Za-z0-9_-]{43}$/.test(key.y || "")
    && !Object.hasOwn(key, "d");
}

function validateChatIdentity(body) {
  const publicKey = body?.publicKey;
  if (!isPublicChatKey(publicKey?.agreement) || !isPublicChatKey(publicKey?.signing)) {
    return { error: "Invalid chat public key" };
  }
  if (!/^(?:cv2\.)?[A-Za-z0-9_-]{100,2000}$/.test(body.wrappedPrivateKey || "")
    || !/^[A-Za-z0-9_-]{22}$/.test(body.recoverySalt || "")
    || !/^[A-Za-z0-9_-]{16}$/.test(body.recoveryIv || "")) {
    return { error: "Invalid encrypted chat key bundle" };
  }
  return {
    publicKey: {
      agreement: {
        kty: "EC", crv: "P-256", x: publicKey.agreement.x, y: publicKey.agreement.y, ext: true, key_ops: [],
      },
      signing: {
        kty: "EC", crv: "P-256", x: publicKey.signing.x, y: publicKey.signing.y, ext: true, key_ops: ["verify"],
      },
    },
    wrappedPrivateKey: body.wrappedPrivateKey,
    recoverySalt: body.recoverySalt,
    recoveryIv: body.recoveryIv,
  };
}

function validChatRequestId(value) {
  return typeof value === "string" && /^\d{1,20}$/.test(value);
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

app.get("/api/vaults/:code/check", codeCheckLimit, asyncHandler(async (req, res) => {
  await ensureDatabase();
  const code = normalizeVaultCode(req.params.code);
  if (!isValidVaultCode(code) || !(await vaultExists(code))) {
    return res.status(404).json({ error: "Code not found" });
  }
  res.json({ valid: true });
}));

app.get("/api/vaults/:code/snippets", lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const snippets = await listSnippets(req.params.code);
  const hasEverAddedSnippet = await vaultHasEverAddedSnippet(req.params.code);
  res.json({ snippets, hasEverAddedSnippet });
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

app.get("/api/vaults/:code/chat/identity", chatReadLimit, requireVault, asyncHandler(async (req, res) => {
  const identity = await getChatIdentity(req.params.code);
  if (!identity) return res.json({ registered: false });
  res.json({
    registered: true,
    peerId: chatPeerId(identity),
    publicKey: JSON.parse(identity.public_key),
    wrappedPrivateKey: identity.wrapped_private_key,
    recoverySalt: identity.recovery_salt,
    recoveryIv: identity.recovery_iv,
  });
}));

app.post("/api/vaults/:code/chat/identity", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  const identity = validateChatIdentity(req.body);
  if (identity.error) return res.status(400).json({ error: identity.error });
  if (!(await createChatIdentity(req.params.code, identity))) {
    return res.status(409).json({ error: "Chat identity already exists." });
  }
  res.status(201).json({ ok: true, peerId: chatPeerId(await getChatIdentity(req.params.code)) });
}));

app.put("/api/vaults/:code/chat/identity", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  const identity = validateChatIdentity(req.body);
  if (identity.error) return res.status(400).json({ error: identity.error });
  if (!identity.wrappedPrivateKey.startsWith("cv2.")) {
    return res.status(400).json({ error: "Chat identity must be encrypted with the vault code." });
  }
  await replaceChatIdentity(req.params.code, identity);
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/chat/requests", chatReadLimit, requireVault, asyncHandler(async (req, res) => {
  const [requests, sentRequests] = await Promise.all([
    listChatRequests(req.params.code),
    listSentChatRequests(req.params.code),
  ]);
  res.json({ requests, sentRequests });
}));

app.post("/api/vaults/:code/chat/invites", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  if (!(await getChatIdentity(req.params.code))) return res.status(409).json({ error: "Set up secure chat before creating an invite" });
  const invite = await createChatInvite(req.params.code);
  const appUrl = PUBLIC_APP_URL || `${req.protocol}://${req.get("host")}`;
  const inviteUrl = new URL("/", appUrl);
  inviteUrl.hash = `chat-invite=${invite.token}`;
  const qrDataUrl = await QRCode.toDataURL(inviteUrl.toString(), { width: 360, margin: 2, errorCorrectionLevel: "H" });
  res.status(201).json({ expiresAt: invite.expiresAt, qrDataUrl });
}));

app.post("/api/vaults/:code/chat/requests", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  const token = typeof req.body?.inviteToken === "string" ? req.body.inviteToken : "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return res.status(400).json({ error: "Choose a valid chat QR code" });
  if (!(await getChatIdentity(req.params.code))) return res.status(409).json({ error: "Set up secure chat before sending a request" });
  const result = await consumeChatInvite(token, req.params.code);
  if (result.error) return res.status(409).json({ error: result.error });
  res.status(result.request.existing ? 200 : 201).json({ id: result.request.id, status: "pending" });
}));

app.post("/api/vaults/:code/chat/requests/:requestId/accept", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.requestId)) return res.status(400).json({ error: "Invalid request" });
  const conversation = await acceptChatRequest(req.params.code, req.params.requestId);
  if (!conversation) return res.status(404).json({ error: "Chat request not found" });
  res.json({ id: conversation.id, peerId: conversation.peerId });
}));

app.post("/api/vaults/:code/chat/requests/:requestId/reject", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.requestId)) return res.status(400).json({ error: "Invalid request" });
  if (!(await rejectChatRequest(req.params.code, req.params.requestId))) {
    return res.status(404).json({ error: "Chat request not found" });
  }
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/chat/conversations", chatReadLimit, requireVault, asyncHandler(async (req, res) => {
  res.json({ conversations: await listChatConversations(req.params.code) });
}));

app.get("/api/vaults/:code/chat/conversations/:id/messages", chatMessageReadLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.id)) return res.status(400).json({ error: "Invalid conversation" });
  const afterId = req.query.after === undefined ? "0" : String(req.query.after);
  if (!/^\d{1,20}$/.test(afterId)) return res.status(400).json({ error: "Invalid message cursor" });
  if (!(await getChatConversation(req.params.code, req.params.id))) {
    return res.status(404).json({ error: "Chat not found" });
  }
  res.json({ messages: await listChatMessages(req.params.id, afterId) });
}));

app.post("/api/vaults/:code/chat/conversations/:id/typing", chatTypingLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.id) || typeof req.body?.typing !== "boolean") {
    return res.status(400).json({ error: "Invalid typing status" });
  }
  if (!(await getChatConversation(req.params.code, req.params.id))) {
    return res.status(404).json({ error: "Chat not found" });
  }
  const key = `${req.params.id}:${req.params.code}`;
  if (req.body.typing) chatTypingStates.set(key, Date.now() + 7000);
  else chatTypingStates.delete(key);
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/chat/conversations/:id/typing", chatReadLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.id)) return res.status(400).json({ error: "Invalid conversation" });
  const conversation = await getChatConversation(req.params.code, req.params.id);
  if (!conversation) return res.status(404).json({ error: "Chat not found" });
  const peerCode = conversation.code_a === req.params.code ? conversation.code_b : conversation.code_a;
  const key = `${req.params.id}:${peerCode}`;
  const expiresAt = chatTypingStates.get(key) || 0;
  if (expiresAt <= Date.now()) chatTypingStates.delete(key);
  res.json({ typing: expiresAt > Date.now() });
}));

app.post("/api/vaults/:code/chat/conversations/:id/messages", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.id)) return res.status(400).json({ error: "Invalid conversation" });
  if (!(await getChatConversation(req.params.code, req.params.id))) {
    return res.status(404).json({ error: "Chat not found" });
  }
  const { iv, ciphertext, signature } = req.body || {};
  if (!/^[A-Za-z0-9_-]{16}$/.test(iv || "")
    || !/^[A-Za-z0-9_-]{22,30000}$/.test(ciphertext || "")
    || !/^[A-Za-z0-9_-]{86}$/.test(signature || "")) {
    return res.status(400).json({ error: "Invalid encrypted message" });
  }
  const message = await insertChatMessage(req.params.id, req.params.code, iv, ciphertext, signature);
  res.status(201).json({ ...message, senderId: chatPeerId(await getChatIdentity(req.params.code)) });
}));

app.delete("/api/vaults/:code/chat/conversations/:id", chatWriteLimit, requireVault, asyncHandler(async (req, res) => {
  if (!validChatRequestId(req.params.id)) return res.status(400).json({ error: "Invalid conversation" });
  if (!(await deleteChatConversation(req.params.code, req.params.id))) {
    return res.status(404).json({ error: "Chat not found" });
  }
  res.json({ ok: true });
}));

app.get("/api/vaults/:code/drive/connect", requireDriveBackend, lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const vault = await getDriveVault(req.params.code);
  if (vault?.drive_refresh_token) {
    return res.status(409).json({ error: "Google Drive is already connected" });
  }
  const config = driveConfiguration();
  const state = createSignedState(
    req.params.code,
    config.encryptionKey,
    Date.now(),
    req.query.remember === "true",
  );
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

app.post("/api/drive/restore", requireDriveBackend, oauthReturnLimit, asyncHandler(async (req, res) => {
  await ensureDatabase();
  if (typeof req.body?.ticket !== "string" || !/^[A-Za-z0-9_-]{40,}$/.test(req.body.ticket)) {
    return res.status(400).json({ error: "Invalid Drive return ticket" });
  }
  const result = await consumeOAuthReturnTicket(pool, req.body?.ticket);
  if (!result) return res.status(404).json({ error: "Drive return expired. Please open your vault again." });
  res.json(result);
}));

app.get("/api/drive/callback", requireDriveBackend, asyncHandler(async (req, res) => {
  let vaultCode;
  let rememberForReturn = false;
  try {
    if (typeof req.query.state !== "string") throw new Error("OAuth callback failed");
    const config = driveConfiguration();
    const state = verifySignedState(req.query.state, config.encryptionKey);
    vaultCode = state.code;
    rememberForReturn = state.remember === true;
    if (typeof req.query.code !== "string" || req.query.error) throw new Error("OAuth callback failed");
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
    const ticket = await issueOAuthReturnTicket(pool, state.code, state.remember === true);
    res.redirect(oauthReturnUrl("connected", ticket));
  } catch {
    const ticket = vaultCode
      ? await issueOAuthReturnTicket(pool, vaultCode, rememberForReturn)
      : null;
    res.redirect(oauthReturnUrl("error", ticket));
  }
}));

function oauthReturnUrl(status, ticket) {
  const path = `/?drive=${encodeURIComponent(status)}${ticket ? `#return=${encodeURIComponent(ticket)}` : ""}`;
  return PUBLIC_APP_URL ? new URL(path, PUBLIC_APP_URL).toString() : path;
}

app.get("/api/vaults/:code/drive/status", requireDriveBackend, lookupLimit, requireVault, asyncHandler(async (req, res) => {
  const vault = await getDriveVault(req.params.code);
  const connected = Boolean(vault?.drive_refresh_token && vault.drive_folder_id);
  res.json({ connected, email: connected ? vault.drive_email : null });
}));

app.post("/api/vaults/:code/drive/disconnect", requireDriveBackend, lookupLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  const accessToken = await getDriveAccessToken(req.params.code, req.driveVault);
  const config = driveConfiguration();
  const refreshToken = decryptRefreshToken(req.driveVault.drive_refresh_token, config.encryptionKey);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const vault = await client.query(
      "SELECT drive_refresh_token FROM vaults WHERE code = $1 FOR UPDATE",
      [req.params.code],
    );
    if (!vault.rows[0]?.drive_refresh_token) {
      throw driveError("Google Drive is no longer connected.", 409, "DRIVE_DISCONNECTED");
    }
    const files = await client.query(
      "SELECT id, drive_file_id FROM files WHERE vault_code = $1 ORDER BY created_at, id",
      [req.params.code],
    );
    await trashTrackedFiles(
      files.rows.map((file) => ({ id: Number(file.id), driveFileId: file.drive_file_id })),
      async (driveFileId) => {
        let response;
        try {
          response = await fetch(
            `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(driveFileId)}`,
            {
              method: "PATCH",
              headers: { ...driveAuthorizationHeader(accessToken), "content-type": "application/json" },
              body: JSON.stringify({ trashed: true }),
            },
          );
        } catch {
          throw driveError(
            "Could not move every ClipVault file to Google Drive Trash. Drive remains connected; please retry.",
            502,
            "GOOGLE_DRIVE_DELETE_FAILED",
          );
        }
        if (!response.ok && response.status !== 404) {
          throw driveError(
            "Could not move every ClipVault file to Google Drive Trash. Drive remains connected; please retry.",
            502,
            "GOOGLE_DRIVE_DELETE_FAILED",
          );
        }
      },
      async (id) => {
        await client.query("DELETE FROM files WHERE vault_code = $1 AND id = $2", [req.params.code, id]);
      },
    );
    await client.query(
      "UPDATE vaults SET drive_refresh_token = NULL, drive_folder_id = NULL, drive_email = NULL WHERE code = $1",
      [req.params.code],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  accessTokenCache.delete(req.params.code);
  try {
    await fetch("https://oauth2.googleapis.com/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshToken }),
    });
  } catch {
    // Local access and file references are already removed.
  }
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

app.get("/api/vaults/:code/files/:id/thumbnail", requireDriveBackend, fileContentLimit, requireVault, requireDriveConnection, asyncHandler(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: "Not found" });
  const file = await getDriveFile(req.params.code, req.params.id);
  if (!file || file.mime !== "application/pdf") return res.status(404).json({ error: "Not found" });
  const accessToken = await getDriveAccessToken(req.params.code, req.driveVault);
  let metadataResponse;
  try {
    metadataResponse = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.drive_file_id)}?fields=thumbnailLink`,
      { headers: driveAuthorizationHeader(accessToken) },
    );
  } catch {
    throw googleError();
  }
  if (!metadataResponse.ok) throw googleError();
  const metadata = await metadataResponse.json().catch(() => null);
  if (typeof metadata?.thumbnailLink !== "string") return res.status(404).json({ error: "Thumbnail not available" });

  let thumbnailUrl;
  try {
    thumbnailUrl = new URL(metadata.thumbnailLink);
  } catch {
    throw googleError();
  }
  if (thumbnailUrl.protocol !== "https:" || !thumbnailUrl.hostname.endsWith(".googleusercontent.com")) {
    throw googleError();
  }

  let thumbnailResponse;
  try {
    thumbnailResponse = await fetch(thumbnailUrl, { headers: driveAuthorizationHeader(accessToken) });
  } catch {
    throw googleError();
  }
  if (!thumbnailResponse.ok || !thumbnailResponse.body) return res.status(404).json({ error: "Thumbnail not available" });
  const contentType = thumbnailResponse.headers.get("content-type") || "image/jpeg";
  if (!contentType.startsWith("image/")) return res.status(404).json({ error: "Thumbnail not available" });
  res.set({
    "Content-Type": contentType,
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, max-age=3600",
  });
  Readable.fromWeb(thumbnailResponse.body).on("error", () => res.destroy()).pipe(res);
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
  if (error?.type === "entity.too.large" && /^\/api\/vaults\/(?:\d{5}|[a-z]{3}-\d{3})\/files$/i.test(req.path)) {
    return res.status(413).json({ error: "File exceeds 4 MB" });
  }
  res.status(500).json({ error: "Server error" });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`ClipVault running on http://localhost:${PORT}`));
}

module.exports = app;
