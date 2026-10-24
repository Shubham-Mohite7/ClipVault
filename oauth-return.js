const crypto = require("crypto");

const OAUTH_RETURN_TTL_MS = 5 * 60 * 1000;

function hashOAuthReturnTicket(ticket) {
  if (typeof ticket !== "string" || !/^[A-Za-z0-9_-]{40,}$/.test(ticket)) {
    throw new Error("Invalid OAuth return ticket");
  }
  return crypto.createHash("sha256").update(ticket).digest("hex");
}

async function issueOAuthReturnTicket(pool, code, remember, now = Date.now()) {
  const ticket = crypto.randomBytes(32).toString("base64url");
  const ticketHash = hashOAuthReturnTicket(ticket);
  await pool.query(
    `INSERT INTO oauth_return_tickets (ticket_hash, vault_code, remember, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [ticketHash, code, remember, now + OAUTH_RETURN_TTL_MS],
  );
  return ticket;
}

async function consumeOAuthReturnTicket(pool, ticket, now = Date.now()) {
  const ticketHash = hashOAuthReturnTicket(ticket);
  const result = await pool.query(
    `DELETE FROM oauth_return_tickets
     WHERE ticket_hash = $1 AND expires_at > $2
     RETURNING vault_code, remember`,
    [ticketHash, now],
  );
  const row = result.rows[0];
  return row ? { code: row.vault_code, remember: row.remember } : null;
}

module.exports = { consumeOAuthReturnTicket, hashOAuthReturnTicket, issueOAuthReturnTicket };
