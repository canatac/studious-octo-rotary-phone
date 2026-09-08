# studious-octo-rotary-phone

## Simple DKIM Signature Service

This application provides an **API endpoint** to generate **DKIM signatures** and send emails using the generated signatures. It uses **Express.js** for the web server and **Nodemailer** for email functionality.

### Key Features
- **Generates DKIM signatures** for emails.
- **Sends emails with DKIM signatures** (via SMTP).
- **Domain deactivation safeguard** with dry-run impact preview + explicit confirmation token.
- **Signing-domain config export/import** for migration portability.
- **Versioned import schema (`v1`)** with dry-run diff before apply.
- **Environment variable configuration** (`.env`).
- **Health check endpoint** (`GET /health`).
- **Signer diagnostics endpoint** (`GET /diagnostics/signer`) with key age, selector status, and last-sign telemetry.
- **Docker support** for easy deployment.

### Domain Deactivation Safeguard API

`POST /domains/{domain}/deactivate`

- `?dryRun=true` returns impact summary (routes/selectors/remaining active domains) without deactivation.
- Without `confirmation=DEACTIVATE_DOMAIN`, API blocks with `409 DEACTIVATION_CONFIRMATION_REQUIRED`.
- API refuses deactivation of the last active signing domain (`409 LAST_SIGNING_DOMAIN_PROTECTED`).
- Confirmed deactivation emits an audit log event `domain_deactivated` with impacted entity count.

### Signing-domain Config Portability API

`GET /signing-domain-config/export`

- Returns a versioned `v1` JSON bundle.
- Private key is excluded by default.
- Add `?secure=true` with valid token (`CONFIG_EXPORT_IMPORT_TOKEN` or `ADMIN_TOKEN`) to include private key.

`POST /signing-domain-config/import`

- Validates `schemaVersion: "v1"` and required config fields.
- `dryRun=true` (default) returns `diff` without applying changes.
- `dryRun=false` applies config in-memory for active process.
- Secure private-key import requires `secure=true` and valid token.

### Recent Updates (2026-07-23)
- **Dependency upgrades**: Updated `nodemailer` to `6.9.15` (security fixes).
- **Test DKIM key**: Added `dkim-private.pem` and `dkim-public.pem` for local testing.
- **Local SMTP testing**: Added instructions for testing with `aiosmtpd` or `smtp-sink`.

---

## Prerequisites
- **Node.js 16+** and **npm**.
- **SMTP server** (e.g., Postfix, Mailpit, or local `aiosmtpd`).
- **DKIM private key** (generate with OpenSSL).

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/canatac/studious-octo-rotary-phone.git
cd studious-octo-rotary-phone
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Generate a DKIM Key (for Testing)
```bash
openssl genrsa -out dkim-private.pem 2048
openssl rsa -in dkim-private.pem -pubout -out dkim-public.pem
```

### 4. Configure Environment Variables
```bash
cp .env.example .env
```

Edit `.env` with your SMTP and DKIM settings:
```ini
# Server
PORT=3000

# DKIM
PRIVATE_KEY_PATH=./dkim-private.pem
DOMAIN_NAME=example.com
KEY_SELECTOR=default

# SMTP (Local Testing - aiosmtpd/smtp-sink)
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
```

---

## Running the Application

### 1. Start the DKIM Server
```bash
node app.js
```

### 2. Start a Local SMTP Server (for Testing)
#### Option A: `aiosmtpd` (Python)
```bash
# Install pip (if not installed)
sudo apt-get install -y python3-pip

# Install aiosmtpd
pip3 install aiosmtpd

# Start SMTP server
python3 -m aiosmtpd -n -l localhost:1025
```

#### Option B: `smtp-sink` (Postfix)
```bash
# Install Postfix
sudo apt-get install -y postfix

# Start SMTP server
smtp-sink 1025 10
```

---

## Testing

### 0. Portability flow (export/import)
```bash
# Export sanitized bundle
curl -X GET "http://localhost:3000/signing-domain-config/export"

# Dry-run import (validation + diff, no apply)
curl -X POST "http://localhost:3000/signing-domain-config/import" \
  -H "Content-Type: application/json" \
  -d '{
    "schemaVersion": "v1",
    "dryRun": true,
    "config": {
      "domainName": "example.com",
      "keySelector": "default",
      "dkimDomains": ["example.com"],
      "privateKeyPath": "./dkim-private.pem"
    }
  }'
```

Migration procedure:
1) Export bundle from source environment.
2) Dry-run import on target and validate `diff`.
3) Apply same payload with `dryRun=false`.

Rollback procedure:
1) Re-import previous exported bundle with `dryRun=false`.
2) Verify `/health` and one `/generate-dkim` smoke request.

### 1. Health Check
```bash
curl -X GET http://localhost:3000/health
```

### 2. Signer Diagnostics
```bash
curl -X GET http://localhost:3000/diagnostics/signer
```

Response contract highlights:
- `status`: `healthy | degraded | critical`
- `selector.domainChecks[]`: per-domain selector check status/code
- DNS TXT multiline records are normalized before DKIM tag validation
- `key.ageDays` and `key.rotationDue` for 90-day key rotation threshold
- `signing.lastSignAt`, `lastSuccessAt`, `lastFailureAt`, `lastFailureCode`

### 3. Send a Test Email (with DKIM)
**Prerequisite**: A running SMTP server (e.g., `aiosmtpd`, `smtp-sink`, or Postfix).

```bash
# Start a local SMTP server (aiosmtpd)
pip3 install aiosmtpd
python3 -m aiosmtpd -n -l localhost:1025
```

```bash
# Send a test email (DKIM signing)
curl -X POST http://localhost:3000/generate-dkim \
-H "Content-Type: application/json" \
-d '{
  "from": "sender@example.com",
  "to": "recipient@example.com",
  "subject": "Test DKIM",
  "text": "Hello from DKIM server"
}'
```

**Troubleshooting**:
- If the email fails to send, check the **DKIM server logs** (`/tmp/dkim-server.log`).
- If `aiosmtpd` is not available, use `smtp-sink` (Postfix) or a real SMTP server.

---

## Docker Deployment

### 1. Build the Docker Image
```bash
docker build -t dkim-service .
```

### 2. Run the Container
```bash
docker run -d -p 3000:3000 --env-file .env -v $(pwd)/dkim-private.pem:/app/dkim-private.pem dkim-service
```

---

## Troubleshooting
| Issue | Solution |
|-------|----------|
| **DKIM signing failed** | Check `PRIVATE_KEY_PATH` in `.env`. |
| **SMTP connection refused** | Verify SMTP server is running (`localhost:1025`). |
| **Invalid DKIM key** | Regenerate the key with OpenSSL. |
| **Port already in use** | Change `PORT` in `.env`. |

---

## License
This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.