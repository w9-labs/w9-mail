# w9-mail

W9 Mail is an email service layer sitting between your applications and
Microsoft SMTP/IMAP/POP3. The backend is written in Rust (Axum + SQLx),
the frontend is Next.js/TypeScript, and deployments are handled through
the provided `install.sh` script.

## Prerequisites

- Ubuntu/Debian server with sudo access
- Git
- curl
- Microsoft 365/Azure app credentials for SMTP/IMAP (Client ID/Secret/Tenant)

## Quick Start

```bash
git clone https://github.com/ShayNeeo/w9-mail.git
cd w9-mail

# Run installer with env inline so sudo receives them
DOMAIN=w9.nu \
BASE_URL=https://w9.nu \
APP_PORT=8080 \
MICROSOFT_CLIENT_ID=... \
MICROSOFT_CLIENT_SECRET_ID=... \
MICROSOFT_TENANT_ID=... \
sudo -E ./install.sh
```

The installer will:

1. Install required packages (Rust toolchain, Node.js, nginx, etc.)
2. Build the backend (`cargo build --release`)
3. Build the frontend (`npm install && npm run build -- --output export`)
4. Drop binaries/static assets into `/opt/w9-mail` and `/var/www/w9-mail`
5. Create `/etc/default/w9-mail` with your environment variables
6. Configure/enable `w9-mail.service` + nginx reverse proxy (Cloudflare-ready)

## Environment Variables

The backend reads configuration from `/etc/default/w9-mail` (created/updated
by `install.sh`). The most important settings are:

| Variable | Description | Default |
| --- | --- | --- |
| `HOST` | Backend bind address | `0.0.0.0` |
| `PORT` | Backend port | `8080` |
| `BASE_URL` | Public base URL | `https://w9.nu` |
| `DATABASE_PATH` | SQLite file path | `/opt/w9-mail/data/w9mail.db` |
| `MICROSOFT_CLIENT_ID` | Azure App (client) ID | _required_ |
| `MICROSOFT_CLIENT_SECRET_ID` | Azure client secret (or use `MICROSOFT_CLIENT_SECRET`) | _required_ |
| `MICROSOFT_CLIENT_VALUE` | Optional custom value | _(empty)_ |
| `MICROSOFT_TENANT_ID` | Azure tenant/directory ID | _required_ |
| `MICROSOFT_REDIRECT_URI` | OAuth redirect URL | `https://w9.nu/api/auth/callback` |
| `MICROSOFT_SCOPE` | OAuth scopes | `https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send` |

> Tip: When running the installer, you can `export` these variables
> beforehand and they will be injected into `/etc/default/w9-mail`.

For local development you can also create `backend/.env` with the same keys.

## Frontend & Backend

- Frontend (Next.js App Router) is located in `frontend/`
- Backend (Axum + SQLx) is located in `backend/`
- Database is SQLite (`/opt/w9-mail/data/w9mail.db` by default)

Key features:

- `/manage` page to add/activate/deactivate email accounts and change passwords
- `/docs` page with API usage
- `/api/send` endpoint sending via Microsoft SMTP (STARTTLS)
- `/api/accounts` CRUD for sender accounts

## Service-to-Service Usage

Applications (such as **w9-tools**) call the API by presenting a JWT in the `Authorization: Bearer` header. Obtain the token by logging in via `/api/auth/login` (with an admin or dev account). Common endpoints:

- `POST /api/send` – send an email using an account/alias. Request body requires camelCase `isHtml`.
- `GET/PUT /api/settings/default-sender` – fetch or change the default sender (account vs alias) used for transactional mail.
- `GET /api/accounts`, `GET /api/aliases` – list available Microsoft-backed senders.

When integrating with w9-tools set `W9_MAIL_API_URL` (usually `https://w9.nu`) and `W9_MAIL_API_TOKEN=<JWT>` inside `/etc/default/w9`. The tools admin panel can then fetch the sender list and let you choose the default without touching w9-mail directly.

## Deployment Notes

- Expects Cloudflare in front of nginx (installs fallback self-signed cert)
- Systemd services: `w9-mail.service` (backend) and `nginx`
- Logs: `sudo journalctl -u w9-mail -f`
- Restart backend: `sudo systemctl restart w9-mail`
- Update code: pull latest, rerun `./install.sh`

## Troubleshooting

- _Email send TLS errors_: Ensure Microsoft credentials/passwords are valid and the account allows SMTP (or uses app password).
- _Account status not updating_: Check that `NEXT_PUBLIC_API_URL` is set correctly so the frontend hits `/api`.
- _Database issues_: Verify `DATABASE_PATH` exists and is writable by `w9-mail` service user (`/opt/w9-mail/data`).
- _nginx SSL warnings_: Provide Cloudflare origin certs or rely on generated self-signed cert when using Cloudflare strict mode.

For additional help, inspect `install.sh` to understand the full provisioning process.