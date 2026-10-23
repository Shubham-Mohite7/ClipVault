# ClipVault

ClipVault stores ready-to-paste text snippets behind a random 5-digit code. No account is required. Local development uses SQLite; deployments can use Supabase Postgres.

## Run locally

Requires Node.js 18 or newer.

```bash
npm install
npm start
```

Open <http://localhost:3000>. Without `DATABASE_URL`, the app uses `clipvault.db` beside `server.js`. If you want to develop against Postgres, copy `.env.example` to `.env`, fill in the values, then load it into the shell before starting:

```bash
set -a
. ./.env
set +a
npm start
```

The server listens on `PORT` if set, or port 3000 otherwise.

## Database schema

The Postgres schema is created lazily once per server instance. SQLite creates its equivalent tables when the local server starts.

| Table | Columns |
|---|---|
| `vaults` | `code` (5-digit primary key), `created_at`, `last_used` |
| `snippets` | `id`, `vault_code` (foreign key with cascade delete), `title`, `content`, `created_at`, `updated_at` |
| `rate_limits` (Postgres) | `key`, `window_start`, `count` (composite primary key on `key`, `window_start`) |

Postgres enables row-level security on all three tables and creates no policies. Use the server's database-owner connection for app access; the Supabase public API has no policies to grant it access. SQLite's rate limiter is in-memory.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/vaults` | Create a vault; returns `{ "code": "12345" }` |
| `GET` | `/api/vaults/:code/snippets` | List snippets; returns `{ "snippets": [...] }` |
| `POST` | `/api/vaults/:code/snippets` | Add a snippet from `{ "title": "...", "content": "..." }`; returns `{ "id": ... }` |
| `PUT` | `/api/vaults/:code/snippets/:id` | Update a snippet |
| `DELETE` | `/api/vaults/:code/snippets/:id` | Delete a snippet |
| `GET` | `/healthz` | Health check; verifies the Postgres connection when configured |
| `GET` | `/api/cron/purge` | Delete old vaults and rate-limit windows; requires `Authorization: Bearer <CRON_SECRET>` |

Snippets are limited to 20,000 characters and 200 per vault; JSON request bodies are limited to 100 KB. The daily Vercel cron removes vaults unused for one year and Postgres rate-limit windows older than two days.

## Security notes

A 5-digit code is weak security, not an account password. Do not store passwords, API keys, or other sensitive data. Use HTTPS in production. Rate limits allow 10 new vaults per hour per IP and 20 code lookups per minute per IP; Postgres deployments store these limits in the database, while local SQLite development uses an in-memory limiter. Postgres errors are returned as generic server errors rather than exposing database details.

## Deploy to Vercel + Supabase

1. Go to <https://supabase.com> and create a new project. Choose a region close to your users and a strong database password; save the password.
2. Click **Connect** and copy the **Transaction pooler** connection string (port `6543`). Replace `[YOUR-PASSWORD]` with the password; URL-encode special characters in it.
3. Create a GitHub repository and push this folder.
4. At <https://vercel.com>, choose **Add New > Project**, import the repository, and select **Other** as the Framework Preset.
5. In **Settings > Environment Variables**, add `DATABASE_URL` and `CRON_SECRET` for Production, Preview, and Development. Generate the cron secret with:

   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

   Redeploy after adding the variables.
6. Open the live URL, create a code, add a snippet, and verify the rows in Supabase's Table Editor. Row-level security should show as enabled.

The Vercel rewrite sends API paths and `/healthz` to the Express function while `/` and other static files are served from `public/`. No region is pinned in `vercel.json`; choose one in Vercel if needed.
