# studious-octo-rotary-phone

## Simple DKIM Signature Service

This application provides an **API endpoint** to generate **DKIM signatures** and send emails using the generated signatures. It uses **Express.js** for the web server and **Nodemailer** for email functionality.

### Key Features
- **Generates DKIM signatures** for emails.
- **Sends emails with DKIM signatures** (via SMTP).
- **Environment variable configuration** (`.env`).
- **Health check endpoint** (`GET /health`).
- **Docker support** for easy deployment.

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
pip install aiosmtpd
python3 -m aiosmtpd -n -l localhost:1025
```

#### Option B: `smtp-sink` (Postfix)
```bash
sudo apt-get install -y postfix
smtp-sink 1025 10
```

---

## Testing

### 1. Health Check
```bash
curl -X GET http://localhost:3000/health
```

### 2. Send a Test Email (with DKIM)
```bash
curl -X POST http://localhost:3000/generate-dkim \
-H "Content-Type: application/json" \
-d '{
  "from": "sender@example.com",
  "to": "recipient@example.com",
  "subject": "Test DKIM",
  "text": "Hello from DKIM server"
}'
```

### 3. Verify DKIM Signature
- Check the **SMTP server logs** for the email.
- Use a **DKIM validator** (e.g., [DKIM Validator](https://dkimvalidator.com/)).

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