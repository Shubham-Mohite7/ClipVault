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
| `files` (Postgres) | `id`, `vault_code`, `drive_file_id`, `name`, `mime`, `size`, `created_at` |

Postgres enables row-level security on all tables and creates no policies. Use the server's database-owner connection for app access; the Supabase public API has no policies to grant it access. SQLite's rate limiter is in-memory.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/vaults` | Create a vault; returns `{ "code": "12345" }` |
| `GET` | `/api/vaults/:code/snippets` | List snippets; returns `{ "snippets": [...] }` |
| `POST` | `/api/vaults/:code/snippets` | Add a snippet from `{ "title": "...", "content": "..." }`; returns `{ "id": ... }` |
| `PUT` | `/api/vaults/:code/snippets/:id` | Update a snippet |
| `DELETE` | `/api/vaults/:code/snippets/:id` | Delete a snippet |
| `GET` | `/api/vaults/:code/drive/connect` | Get the Google consent URL |
| `GET` | `/api/vaults/:code/drive/status` | Check Drive connection |
| `POST` | `/api/vaults/:code/drive/disconnect` | Disconnect Drive; app file references are removed but files stay in Drive |
| `GET` | `/api/vaults/:code/files` | List attached file metadata |
| `POST` | `/api/vaults/:code/files?name=<filename>` | Upload a raw image/PDF body |
| `GET` | `/api/vaults/:code/files/:id/content` | View or download a file (`?download=1`) |
| `DELETE` | `/api/vaults/:code/files/:id` | Move a file to the user's Drive trash |
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

To collect page views, enable **Web Analytics** in the Vercel project dashboard and redeploy. The static HTML pages include Vercel's `/_vercel/insights/script.js` integration; the React component and npm package are not needed for this project.

The public privacy policy and Terms of Service are served at `/privacy.html` and `/terms.html`, and linked from the homepage. For Google OAuth branding, configure the production homepage, privacy-policy, and terms URLs on your verified custom domain.

The public pages include canonical URLs for `https://www.clipvault.lol`, social sharing metadata, WebApplication structured data on the homepage, and a sitemap at `/sitemap.xml`. After deployment, add the sitemap in Google Search Console and request indexing for the homepage. A sitemap and metadata help search engines understand the site but do not guarantee rankings or indexing.

## Google Drive files

Users can connect their own Google Drive and attach images or PDFs to a vault. ClipVault requests only the `drive.file` and `email` scopes, creates a `ClipVault` folder, and uploads files there. Refresh tokens are encrypted at rest with AES-256-GCM; access tokens are kept only in a short-lived per-instance memory cache. The app can access only files created by ClipVault through the granted `drive.file` scope. Disconnecting revokes access when possible and removes the app's file references; it does not delete the user's Drive files.

Drive attachments require Postgres and all four environment variables below. In local development, set `GOOGLE_REDIRECT_URI=http://localhost:3000/api/drive/callback`; in production, use `https://YOUR-APP.vercel.app/api/drive/callback`. Generate a 32-byte encryption key with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, and `TOKEN_ENC_KEY` locally and in Vercel. Never commit real values. A Google client ID/secret is not a substitute for keeping `TOKEN_ENC_KEY` private.

### Google Cloud setup

1. Go to <https://console.cloud.google.com> and create a project.
2. Open **APIs & Services > Library** and enable **Google Drive API**.
3. Open **APIs & Services > OAuth consent screen** (Google Auth Platform), choose **External**, and fill in the app name, support email, and developer email. Add the `drive.file` and `email` scopes. Set the publishing status to **In production**; in Testing mode, refresh tokens expire after 7 days and only listed test users can sign in.
4. Under **Credentials**, choose **Create credentials > OAuth client ID > Web application**. Add these Authorized redirect URIs:
   - `http://localhost:3000/api/drive/callback`
   - `https://YOUR-APP.vercel.app/api/drive/callback`
5. Copy the Client ID and Client secret into `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. In Vercel, configure all four Google Drive variables, along with the existing `DATABASE_URL` and `CRON_SECRET`, then redeploy.

Files are limited to 4 MB each and 50 per vault. Supported formats are PNG, JPEG, GIF, WebP, and PDF; file contents are checked against their signatures, and SVG is not accepted. Rate limiting allows 30 uploads per hour per IP and 60 file-content requests per minute per IP, in addition to the existing 20 code lookups per minute.

The vault's 5-digit code is the only app-level access control: anyone who knows it can view that vault's file list and files. Do not use it for sensitive material; a longer code or optional PIN is recommended.
