/**
 * DKIM Signature Generator and Email Sender
 * 
 * This application provides an API endpoint to generate DKIM signatures
 * and send emails using the generated signatures. It uses Express.js for
 * the web server and Nodemailer for email functionality.
 * 
 * Key Features:
 * - Generates DKIM signatures for emails
 * - Sends emails with DKIM signatures
 * - Uses environment variables for configuration
 * - Provides a single POST endpoint for email sending
 * 
 * Setup:
 * 1. Ensure all required environment variables are set in a .env file
 * 2. Install dependencies using `npm install`
 * 3. Run the server using `node app.js`
 * 
 * Usage:
 * Send a POST request to /generate-dkim with the following JSON body:
 * {
 *   "from": "sender@example.com",
 *   "to": "recipient@example.com",
 *   "subject": "Email Subject",
 *   "text": "Email Body"
 * }
 * 
 * The server will generate a DKIM signature and send the email.
 * 
 * Note: Ensure that the SMTP server and DKIM private key are properly configured.
 */

// Import required modules
const dotenv = require('dotenv');
const express = require('express');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const dns = require('dns').promises;

// Load environment variables
dotenv.config();

/**
 * Express application setup
 * @type {import('express').Application}
 */
const app = express();

const DEACTIVATION_CONFIRMATION_TOKEN = 'DEACTIVATE_DOMAIN';
const deactivatedDomains = new Set();

const normalizeDomain = (value) => String(value || '')
  .trim()
  .toLowerCase()
  .replace(/^@+/, '')
  .replace(/[>\s]+$/g, '');

const parseConfiguredDomains = () => {
  const raw = process.env.DKIM_DOMAINS || process.env.DOMAIN_NAME || '';
  return raw
    .split(',')
    .map((s) => normalizeDomain(s))
    .filter(Boolean);
};

const buildDeactivationImpact = (domain, configuredDomains) => ({
  domain,
  impactedRoutes: ['/generate-dkim'],
  impactedSelectors: [process.env.KEY_SELECTOR || 'default'],
  remainingActiveDomains: configuredDomains.filter(
    (candidate) => candidate !== domain && !deactivatedDomains.has(candidate),
  ),
});

// Middleware to parse JSON bodies (attachments can make payload large).
const requestBodyLimit = process.env.REQUEST_BODY_LIMIT || '50mb';
app.use(express.json({ limit: requestBodyLimit }));
app.use(express.urlencoded({ extended: true, limit: requestBodyLimit }));

app.post('/domains/:domain/deactivate', (req, res) => {
  const configuredDomains = parseConfiguredDomains();
  const domain = normalizeDomain(req.params.domain);
  const dryRunRequested = req.query.dryRun === 'true' || req.body?.dryRun === true;
  const fallbackDomain = normalizeDomain(process.env.DOMAIN_NAME);
  const impact = buildDeactivationImpact(domain, configuredDomains);

  if (!domain || !configuredDomains.includes(domain)) {
    return res.status(404).json({
      status: 'error',
      code: 'DOMAIN_NOT_CONFIGURED',
      message: 'Domain is not configured for DKIM signing',
      configuredDomains,
    });
  }

  if (dryRunRequested) {
    return res.status(200).json({
      status: 'dry_run',
      domain,
      impact,
      fallbackDomainWillRotate: fallbackDomain === domain,
      proposedFallbackDomain: fallbackDomain === domain ? impact.remainingActiveDomains[0] || null : fallbackDomain,
      remediationSteps: [
        'Migrate aliases/signing traffic to another active domain',
        `Resubmit with confirmation='${DEACTIVATION_CONFIRMATION_TOKEN}' to apply`,
      ],
    });
  }

  const confirmation = String(req.body?.confirmation || '').trim();
  if (confirmation !== DEACTIVATION_CONFIRMATION_TOKEN) {
    return res.status(409).json({
      status: 'error',
      code: 'DEACTIVATION_CONFIRMATION_REQUIRED',
      message: 'Domain deactivation blocked. Explicit confirmation token required.',
      requiredConfirmation: DEACTIVATION_CONFIRMATION_TOKEN,
      impact,
      remediationSteps: [
        'Run dry-run first: POST /domains/{domain}/deactivate?dryRun=true',
        `Resubmit with confirmation='${DEACTIVATION_CONFIRMATION_TOKEN}'`,
      ],
    });
  }

  if (impact.remainingActiveDomains.length === 0) {
    return res.status(409).json({
      status: 'error',
      code: 'LAST_SIGNING_DOMAIN_PROTECTED',
      message: 'Cannot deactivate the last active signing domain.',
      impact,
      remediationSteps: ['Add another active signing domain before deactivation.'],
    });
  }

  deactivatedDomains.add(domain);
  console.log('[AUDIT] domain_deactivated', JSON.stringify({
    domain,
    impactedEntitiesCount: 1 + impact.impactedRoutes.length + impact.impactedSelectors.length,
    remainingActiveDomains: impact.remainingActiveDomains,
    fallbackDomain,
    fallbackDomainRotated: fallbackDomain === domain,
    proposedFallbackDomain: fallbackDomain === domain ? impact.remainingActiveDomains[0] : fallbackDomain,
  }));

  return res.status(200).json({
    status: 'success',
    message: 'Domain deactivated with safeguard confirmation.',
    domain,
    impact,
    fallbackDomainRotated: fallbackDomain === domain,
    fallbackDomain: fallbackDomain === domain ? impact.remainingActiveDomains[0] : fallbackDomain,
  });
});

/**
 * Read private key from file
 * @type {string}
 */
const privateKeyPath = path.join(__dirname, process.env.PRIVATE_KEY_PATH);
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

/**
 * Route to generate DKIM signature and send email
 * @route POST /generate-dkim
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
app.post('/generate-dkim', async (req, res) => {
  console.log('Received request:', JSON.stringify(req.body, null, 2));

  const { from, to, subject, text, html, attachments } = req.body;

  if (!from || !to || !subject || (!text && !html)) {
    res.status(400).json({
      status: 'error',
      message: 'Missing required fields: from, to, subject, and text or html',
    });
    return;
  }

  // Derive a plain-text fallback from HTML when caller only provided html.
  // Sending balises HTML inside a text/plain part triggers anti-spam heuristics
  // (MIME_HTML_ONLY / MPART_ALT_DIFF) and hurts inbox placement.
  const htmlToPlainText = (h) => String(h)
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<\/?(p|div|br|li|tr|h[1-6])[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  const plainText = (typeof text === 'string' && text.trim().length > 0)
    ? text
    : (html ? htmlToPlainText(html) : '');

  // Create a message object
  const message = {
    from,
    to,
    subject,
    text: plainText,
    html,
  };

  // Determine DKIM signing domain from the From address (multi-domain support).
  // Falls back to DOMAIN_NAME when the From domain is not explicitly allowed.
  const fromDomain = normalizeDomain(String(from).split('@').pop());
  const allowedDomains = parseConfiguredDomains();
  const fallbackDomain = normalizeDomain(process.env.DOMAIN_NAME);
  const signingDomain = allowedDomains.includes(fromDomain)
    ? fromDomain
    : fallbackDomain;

  if (deactivatedDomains.has(signingDomain)) {
    return res.status(409).json({
      status: 'error',
      code: 'SIGNING_DOMAIN_DEACTIVATED',
      message: `Signing domain '${signingDomain}' is deactivated.`,
      impact: buildDeactivationImpact(signingDomain, allowedDomains),
      remediationSteps: [
        'Use a sender address from an active DKIM domain',
        `Or reactivate '${signingDomain}' before retrying`,
      ],
    });
  }

  console.log(`DKIM sign: from=${fromDomain} d=${signingDomain} s=${process.env.KEY_SELECTOR}`);

  // Create a transporter with DKIM configuration
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: {
      rejectUnauthorized: false
    },
    dkim: {
      domainName: signingDomain,
      keySelector: process.env.KEY_SELECTOR,
      privateKey: privateKey
    }
  });

  const normalizedAttachments = Array.isArray(attachments)
    ? attachments
        .filter((att) => att && typeof att.filename === 'string' && typeof att.dataBase64 === 'string' && att.dataBase64.trim().length > 0)
        .map((att) => ({
          filename: String(att.filename).trim() || 'attachment.bin',
          content: Buffer.from(att.dataBase64, 'base64'),
          contentType: typeof att.contentType === 'string' && att.contentType.trim().length > 0
            ? att.contentType.trim()
            : undefined,
        }))
    : [];

  // Define the email options
  const mailOptions = {
    from,
    to,
    subject,
    text: message.text,
    html: message.html,
    attachments: normalizedAttachments,
  };

  try {
    // Send mail with defined transport object
    const info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);

    const accepted = Array.isArray(info.accepted) ? info.accepted : [];
    const rejected = Array.isArray(info.rejected) ? info.rejected : [];
    const pending = Array.isArray(info.pending) ? info.pending : [];
    const acceptedByRemoteMx = accepted.length > 0;

    const smtpHost = process.env.SMTP_HOST || null;
    const smtpPort = Number.parseInt(process.env.SMTP_PORT, 10) || null;
    let remoteIp = null;
    if (smtpHost) {
      try {
        const resolved = await dns.lookup(smtpHost);
        remoteIp = resolved && resolved.address ? resolved.address : null;
      } catch (lookupError) {
        console.warn('SMTP host lookup failed:', lookupError && lookupError.message ? lookupError.message : lookupError);
      }
    }

    res.status(acceptedByRemoteMx ? 200 : 502).json({
      message: acceptedByRemoteMx
        ? 'Email accepted by upstream SMTP server'
        : 'Email was not accepted by upstream SMTP server',
      messageId: info.messageId,
      status: acceptedByRemoteMx ? 'success' : 'error',
      acceptedByRemoteMx,
      accepted,
      rejected,
      pending,
      response: info.response || null,
      envelope: info.envelope || null,
      smtpHost,
      smtpPort,
      remoteIp,
    });
    return;
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({
      status: 'error',
      error: 'Failed to send email',
      message: error && error.message ? error.message : 'Unknown SMTP error',
      response: error && error.response ? error.response : null,
      code: error && error.code ? error.code : null,
    });
  }
});

// Return JSON (not HTML) for oversized payloads to keep frontend error handling deterministic.
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large' || err.status === 413)) {
    return res.status(413).json({
      status: 'error',
      code: 'PAYLOAD_TOO_LARGE',
      message: `Request body too large. Increase REQUEST_BODY_LIMIT (current: ${requestBodyLimit}).`,
    });
  }
  return next(err);
});

/**
 * Health check route
 * @route GET /health
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {void}
 */
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Service is running' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
