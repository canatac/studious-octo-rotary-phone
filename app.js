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
const { registerDomainDeactivationRoute } = require('./routes/domain_deactivation');
const { registerSigningDomainConfigRoutes } = require('./routes/signing_domain_config');
const { registerMtaStsRoutes } = require('./routes/mta_sts');
const { registerDmarcRoutes } = require('./routes/dmarc');
const tlsRptRoutes = require('./routes/tls_rpt');

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
  if (runtimeConfig && Array.isArray(runtimeConfig.dkimDomains) && runtimeConfig.dkimDomains.length > 0) {
    return runtimeConfig.dkimDomains;
  }
  const raw = process.env.DKIM_DOMAINS || process.env.DOMAIN_NAME || '';
  return raw
    .split(',')
    .map((s) => normalizeDomain(s))
    .filter(Boolean);
};

const resolveSigningDomain = (fromAddress, configuredDomains) => {
  const fromDomain = normalizeDomain(String(fromAddress).split('@').pop());
  if (configuredDomains.includes(fromDomain)) {
    return { fromDomain, signingDomain: fromDomain };
  }

  const fallback = normalizeDomain((runtimeConfig && runtimeConfig.domainName) || process.env.DOMAIN_NAME);
  return { fromDomain, signingDomain: fallback || configuredDomains[0] || '' };
};

const buildDeactivationImpact = (domain, configuredDomains) => ({
  domain,
  wouldDisableSigningForDomain: true,
  remainingActiveDomains: configuredDomains.filter(
    (candidate) => candidate !== domain && !deactivatedDomains.has(candidate),
  ),
  impactedRoutes: ['/generate-dkim'],
  impactedSelectors: [(runtimeConfig && runtimeConfig.keySelector) || process.env.KEY_SELECTOR || 'default'],
});

const signerDiagnosticsState = {
  startedAt: new Date().toISOString(),
  totalSignAttempts: 0,
  totalSignSuccess: 0,
  totalSignFailure: 0,
  lastSignAt: null,
  lastSuccessAt: null,
  lastFailureAt: null,
  lastFailureCode: null,
  lastFailureMessage: null,
};

const resolveSignerSummary = ({ selectorConfigured, keyFileExists, domainChecks }) => {
  if (!selectorConfigured || !keyFileExists || domainChecks.some((entry) => entry.status === 'critical')) {
    return 'critical';
  }
  if (domainChecks.some((entry) => entry.status === 'degraded') || signerDiagnosticsState.lastFailureAt) {
    return 'degraded';
  }
  return 'healthy';
};

const normalizeTxtSegment = (segment) => String(segment || '')
  .trim()
  .replace(/^"|"$/g, '');

const parseTxtTagMap = (segments) => {
  const raw = (Array.isArray(segments) ? segments : [segments])
    .map((segment) => normalizeTxtSegment(segment))
    .join('');

  const tags = raw
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const eqIndex = part.indexOf('=');
      if (eqIndex <= 0) {
        return acc;
      }
      const key = part.slice(0, eqIndex).trim().toLowerCase();
      const value = part.slice(eqIndex + 1).trim();
      if (key.length > 0) {
        acc[key] = value;
      }
      return acc;
    }, {});

  return { raw, tags };
};

const remediationByCode = {
  DOMAIN_NOT_CONFIGURED: 'Add the domain to DKIM_DOMAINS (or DOMAIN_NAME) and redeploy.',
  SELECTOR_MISSING: 'Set KEY_SELECTOR in environment and redeploy the service.',
  DKIM_SELECTOR_LOOKUP_FAILED: 'Publish TXT at <selector>._domainkey.<domain> with v=DKIM1; p=<public-key>.',
  DKIM_SELECTOR_SHAPE_INVALID: 'Fix DKIM TXT shape. Expected v=DKIM1 and non-empty p= tag.',
  SPF_LOOKUP_FAILED: 'Publish SPF TXT on the root domain, e.g. v=spf1 include:<provider> ~all.',
  SPF_MISSING: 'Add SPF TXT record on the root domain with v=spf1 policy.',
  MX_LOOKUP_FAILED: 'Publish at least one MX record for the domain.',
};

const evaluateDomainReadiness = async (domain) => {
  const normalizedDomain = normalizeDomain(domain);
  const configuredDomains = parseConfiguredDomains();
  const selector = (runtimeConfig.keySelector || process.env.KEY_SELECTOR || '').trim();

  if (!normalizedDomain || !configuredDomains.includes(normalizedDomain)) {
    return {
      domain: normalizedDomain,
      ready: false,
      code: 'DOMAIN_NOT_CONFIGURED',
      checks: [],
      remediation: remediationByCode.DOMAIN_NOT_CONFIGURED,
    };
  }

  const checks = [];

  if (!selector) {
    checks.push({
      control: 'dkim_selector',
      status: 'fail',
      code: 'SELECTOR_MISSING',
      detail: 'KEY_SELECTOR is not configured',
      remediation: remediationByCode.SELECTOR_MISSING,
    });
  } else {
    const dkimHost = `${selector}._domainkey.${normalizedDomain}`;
    try {
      const records = await dns.resolveTxt(dkimHost);
      const parsedRecords = records.map((segments) => parseTxtTagMap(segments));
      const dkimRecord = parsedRecords.find((entry) => String(entry.tags.v || '').toLowerCase() === 'dkim1');
      const publicKey = String((dkimRecord && dkimRecord.tags && dkimRecord.tags.p) || '').trim();
      if (dkimRecord && publicKey.length > 0) {
        checks.push({
          control: 'dkim_selector',
          status: 'pass',
          code: 'DKIM_SELECTOR_OK',
          detail: `TXT found on ${dkimHost} with v=DKIM1 and p=`,
          remediation: null,
        });
      } else {
        checks.push({
          control: 'dkim_selector',
          status: 'fail',
          code: 'DKIM_SELECTOR_SHAPE_INVALID',
          detail: `TXT found on ${dkimHost} but required tags are missing`,
          remediation: remediationByCode.DKIM_SELECTOR_SHAPE_INVALID,
        });
      }
    } catch (error) {
      checks.push({
        control: 'dkim_selector',
        status: 'fail',
        code: 'DKIM_SELECTOR_LOOKUP_FAILED',
        detail: error && error.code ? error.code : 'DNS lookup failed',
        remediation: remediationByCode.DKIM_SELECTOR_LOOKUP_FAILED,
      });
    }
  }

  try {
    const txtRecords = await dns.resolveTxt(normalizedDomain);
    const flattenedTxt = txtRecords.map((segments) => parseTxtTagMap(segments).raw.toLowerCase());
    const hasSpf = flattenedTxt.some((entry) => entry.startsWith('v=spf1'));
    checks.push({
      control: 'spf_record',
      status: hasSpf ? 'pass' : 'fail',
      code: hasSpf ? 'SPF_OK' : 'SPF_MISSING',
      detail: hasSpf ? `SPF TXT found on ${normalizedDomain}` : `No SPF TXT (v=spf1) found on ${normalizedDomain}`,
      remediation: hasSpf ? null : remediationByCode.SPF_MISSING,
    });
  } catch (error) {
    checks.push({
      control: 'spf_record',
      status: 'fail',
      code: 'SPF_LOOKUP_FAILED',
      detail: error && error.code ? error.code : 'DNS lookup failed',
      remediation: remediationByCode.SPF_LOOKUP_FAILED,
    });
  }

  try {
    const mxRecords = await dns.resolveMx(normalizedDomain);
    const hasMx = Array.isArray(mxRecords) && mxRecords.length > 0;
    checks.push({
      control: 'mx_record',
      status: hasMx ? 'pass' : 'fail',
      code: hasMx ? 'MX_OK' : 'MX_LOOKUP_FAILED',
      detail: hasMx ? `MX records found for ${normalizedDomain}` : `No MX records found for ${normalizedDomain}`,
      remediation: hasMx ? null : remediationByCode.MX_LOOKUP_FAILED,
    });
  } catch (error) {
    checks.push({
      control: 'mx_record',
      status: 'fail',
      code: 'MX_LOOKUP_FAILED',
      detail: error && error.code ? error.code : 'DNS lookup failed',
      remediation: remediationByCode.MX_LOOKUP_FAILED,
    });
  }

  // SPF/DKIM alignment check (issue #28 fix)
  const dkimCheck = checks.find((c) => c.control === 'dkim_selector');
  const spfCheck = checks.find((c) => c.control === 'spf_record');
  const isAligned = dkimCheck && spfCheck && dkimCheck.status === 'pass' && spfCheck.status === 'pass';
  if (isAligned) {
    checks.push({ control: 'alignment', status: 'pass', code: 'SPF_DKIM_ALIGNED', detail: `SPF and DKIM aligned for ${normalizedDomain}`, remediation: null });
  } else if (dkimCheck && dkimCheck.status === 'pass') {
    checks.push({ control: 'alignment', status: 'degraded', code: 'SPF_DKIM_ALIGNMENT_PARTIAL', detail: `DKIM configured but SPF missing/invalid for ${normalizedDomain}`, remediation: 'Add SPF record to achieve full alignment' });
  }
  const failingChecks = checks.filter((check) => check.status === 'fail');
  const degradedChecks = checks.filter((check) => check.status === 'degraded');
  return {
    domain: normalizedDomain,
    ready: failingChecks.length === 0,
    code: failingChecks.length === 0 ? (degradedChecks.length > 0 ? 'DOMAIN_READY_DEGRADED' : 'DOMAIN_READY') : 'DOMAIN_NOT_READY',
    checks,
    remediation: failingChecks.map((check) => check.remediation).filter(Boolean),
    checkedAt: new Date().toISOString(),
  };
};

// Middleware to parse JSON bodies (attachments can make payload large).
const requestBodyLimit = process.env.REQUEST_BODY_LIMIT || '50mb';
app.use(express.json({ limit: requestBodyLimit }));
app.use(express.urlencoded({ extended: true, limit: requestBodyLimit }));

app.post('/domains/:domain/deactivate', (req, res) => {
  const configuredDomains = parseConfiguredDomains();
  const domain = normalizeDomain(req.params.domain);
  const dryRunRequested = req.query.dryRun === 'true' || req.body?.dryRun === true;

  if (!domain || !configuredDomains.includes(domain)) {
    res.status(404).json({
      status: 'error',
      code: 'DOMAIN_NOT_CONFIGURED',
      message: 'Domain is not configured for DKIM signing',
      configuredDomains,
    });
    return;
  }

  const impact = buildDeactivationImpact(domain, configuredDomains);

  if (dryRunRequested) {
    res.status(200).json({
      status: 'dry_run',
      domain,
      impact,
      remediationSteps: [
        'Migrate aliases/signing traffic to another active domain',
        `Repeat request with confirmation='${DEACTIVATION_CONFIRMATION_TOKEN}' to confirm deactivation`,
      ],
    });
    return;
  }

  const confirmation = String(req.body?.confirmation || '').trim();
  if (confirmation !== DEACTIVATION_CONFIRMATION_TOKEN) {
    res.status(409).json({
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
    return;
  }

  if (impact.remainingActiveDomains.length === 0) {
    res.status(409).json({
      status: 'error',
      code: 'LAST_SIGNING_DOMAIN_PROTECTED',
      message: 'Cannot deactivate the last active signing domain.',
      impact,
      remediationSteps: ['Add another active signing domain before deactivation.'],
    });
    return;
  }

  deactivatedDomains.add(domain);
  console.log('[AUDIT] domain_deactivated', JSON.stringify({
    domain,
    impactedEntitiesCount: 1 + impact.impactedRoutes.length + impact.impactedSelectors.length,
    remainingActiveDomains: impact.remainingActiveDomains,
  }));

  res.status(200).json({
    status: 'success',
    message: 'Domain deactivated with safeguard confirmation.',
    domain,
    impact,
  });
});

app.get('/domains/:domain/readiness', async (req, res) => {
  const readiness = await evaluateDomainReadiness(req.params.domain);
  if (readiness.code === 'DOMAIN_NOT_CONFIGURED') {
    res.status(404).json({
      status: 'error',
      code: readiness.code,
      domain: readiness.domain,
      ready: false,
      checks: readiness.checks,
      remediation: [readiness.remediation],
      checkedAt: new Date().toISOString(),
    });
    return;
  }

  res.status(200).json({
    status: readiness.ready ? 'ready' : 'not_ready',
    code: readiness.code,
    domain: readiness.domain,
    ready: readiness.ready,
    checks: readiness.checks,
    remediation: readiness.remediation,
    checkedAt: readiness.checkedAt,
  });
});

const normalizeDomainList = (value) => String(value || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const toAbsolutePath = (candidatePath) => {
  if (!candidatePath) {
    return null;
  }
  return path.isAbsolute(candidatePath)
    ? candidatePath
    : path.join(__dirname, candidatePath);
};

const readPrivateKeyFromPath = (candidatePath) => {
  const absolutePath = toAbsolutePath(candidatePath);
  if (!absolutePath) {
    throw new Error('PRIVATE_KEY_PATH is required');
  }
  return fs.readFileSync(absolutePath, 'utf8');
};

let runtimeConfig = {
  schemaVersion: 'v1',
  domainName: (process.env.DOMAIN_NAME || '').trim().toLowerCase(),
  keySelector: (process.env.KEY_SELECTOR || '').trim(),
  dkimDomains: normalizeDomainList(process.env.DKIM_DOMAINS || process.env.DOMAIN_NAME || ''),
  privateKeyPath: process.env.PRIVATE_KEY_PATH,
};

let privateKey = readPrivateKeyFromPath(runtimeConfig.privateKeyPath);

const secureConfigToken = process.env.CONFIG_EXPORT_IMPORT_TOKEN || process.env.ADMIN_TOKEN || '';

registerDomainDeactivationRoute({
  app,
  parseConfiguredDomains,
  normalizeDomain,
  buildDeactivationImpact,
  deactivatedDomains,
  DEACTIVATION_CONFIRMATION_TOKEN,
});

registerSigningDomainConfigRoutes({
  app,
  getRuntimeConfig: () => runtimeConfig,
  setRuntimeConfig: (nextConfig) => {
    runtimeConfig = nextConfig;
  },
  getPrivateKey: () => privateKey,
  setPrivateKey: (nextPrivateKey) => {
    privateKey = nextPrivateKey;
  },
  readPrivateKeyFromPath,
  secureConfigToken,
});

// TLS-RPT routes (issue #35)
tlsRptRoutes.registerTlsRptRoutes(app);

// MTA-STS routes (issue #32)
registerMtaStsRoutes(app);

// DMARC routes (issue #36)
registerDmarcRoutes(app);

/**
 * Route to generate DKIM signature and send email
 * @route POST /generate-dkim
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
app.post('/generate-dkim', async (req, res) => {
  console.log('Received request:', JSON.stringify(req.body, null, 2));
  signerDiagnosticsState.totalSignAttempts += 1;
  signerDiagnosticsState.lastSignAt = new Date().toISOString();

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
  const allowedDomains = parseConfiguredDomains();
  const { fromDomain, signingDomain } = resolveSigningDomain(from, allowedDomains);

  if (deactivatedDomains.has(signingDomain)) {
    res.status(409).json({
      status: 'error',
      code: 'SIGNING_DOMAIN_DEACTIVATED',
      message: `Signing domain '${signingDomain}' is deactivated.`,
      impact: buildDeactivationImpact(signingDomain, allowedDomains),
      remediationSteps: [
        'Use a sender address on an active DKIM domain',
        `Or reactivate domain before calling /generate-dkim again`,
      ],
    });
    return;
  }

  console.log(`DKIM sign: from=${fromDomain} d=${signingDomain} s=${runtimeConfig.keySelector}`);

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
      keySelector: runtimeConfig.keySelector,
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

    if (acceptedByRemoteMx) {
      signerDiagnosticsState.totalSignSuccess += 1;
      signerDiagnosticsState.lastSuccessAt = new Date().toISOString();
      signerDiagnosticsState.lastFailureCode = null;
      signerDiagnosticsState.lastFailureMessage = null;
    } else {
      signerDiagnosticsState.totalSignFailure += 1;
      signerDiagnosticsState.lastFailureAt = new Date().toISOString();
      signerDiagnosticsState.lastFailureCode = 'UPSTREAM_REJECTED';
      signerDiagnosticsState.lastFailureMessage = 'SMTP upstream did not accept recipients';
    }

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
    signerDiagnosticsState.totalSignFailure += 1;
    signerDiagnosticsState.lastFailureAt = new Date().toISOString();
    signerDiagnosticsState.lastFailureCode = error && error.code ? error.code : 'SEND_ERROR';
    signerDiagnosticsState.lastFailureMessage = error && error.message ? error.message : 'Unknown SMTP error';
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

app.get('/diagnostics/signer', async (req, res) => {
  const selector = (runtimeConfig.keySelector || process.env.KEY_SELECTOR || '').trim();
  const selectorConfigured = selector.length > 0;
  const keyAbsolutePath = toAbsolutePath(runtimeConfig.privateKeyPath);
  const keyFileExists = keyAbsolutePath ? fs.existsSync(keyAbsolutePath) : false;

  let keyLastModifiedAt = null;
  let keyAgeDays = null;
  if (keyFileExists) {
    try {
      const stats = fs.statSync(keyAbsolutePath);
      keyLastModifiedAt = stats.mtime.toISOString();
      keyAgeDays = Math.floor((Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24));
    } catch (e) {
      keyLastModifiedAt = null;
      keyAgeDays = null;
    }
  }

  const activeDomains = runtimeConfig.dkimDomains.filter((domain) => !deactivatedDomains.has(domain));
  const domainChecks = await Promise.all(activeDomains.map(async (domain) => {
    const host = `${selector}._domainkey.${domain}`;

    if (!selectorConfigured) {
      return {
        domain,
        host,
        status: 'critical',
        code: 'SELECTOR_MISSING',
        detail: 'No KEY_SELECTOR configured',
      };
    }

    try {
      const records = await dns.resolveTxt(host);
      const parsedRecords = records.map((segments) => parseTxtTagMap(segments));
      const dkimRecord = parsedRecords.find((entry) => String(entry.tags.v || '').toLowerCase() === 'dkim1');
      const hasVersion = Boolean(dkimRecord);
      const hasPublicKey = Boolean(dkimRecord && Object.prototype.hasOwnProperty.call(dkimRecord.tags, 'p'));
      if (hasVersion && hasPublicKey) {
        return {
          domain,
          host,
          status: 'healthy',
          code: 'DKIM_SELECTOR_OK',
          detail: 'Selector TXT parsed (multiline-safe) with v=DKIM1 and p=',
        };
      }
      return {
        domain,
        host,
        status: 'degraded',
        code: 'DKIM_SELECTOR_SHAPE_INVALID',
        detail: `Selector TXT malformed after multiline parse (records=${records.length})`,
      };
    } catch (error) {
      return {
        domain,
        host,
        status: 'critical',
        code: 'DKIM_SELECTOR_LOOKUP_FAILED',
        detail: error && error.code ? error.code : 'DNS lookup failed',
      };
    }
  }));

  const status = resolveSignerSummary({ selectorConfigured, keyFileExists, domainChecks });

  res.status(200).json({
    status,
    selector: {
      value: selector || null,
      configured: selectorConfigured,
      activeDomains,
      domainChecks,
    },
    key: {
      path: runtimeConfig.privateKeyPath || null,
      exists: keyFileExists,
      lastModifiedAt: keyLastModifiedAt,
      ageDays: keyAgeDays,
      rotationWindowDays: 90,
      rotationDue: keyAgeDays === null ? null : keyAgeDays >= 90,
    },
    signing: {
      since: signerDiagnosticsState.startedAt,
      totalAttempts: signerDiagnosticsState.totalSignAttempts,
      totalSuccess: signerDiagnosticsState.totalSignSuccess,
      totalFailure: signerDiagnosticsState.totalSignFailure,
      lastSignAt: signerDiagnosticsState.lastSignAt,
      lastSuccessAt: signerDiagnosticsState.lastSuccessAt,
      lastFailureAt: signerDiagnosticsState.lastFailureAt,
      lastFailureCode: signerDiagnosticsState.lastFailureCode,
      lastFailureMessage: signerDiagnosticsState.lastFailureMessage,
    },
    operationalPlaybook: {
      healthy: 'No action required.',
      degraded: 'Validate selector TXT value and inspect signer failures.',
      critical: 'Restore KEY_SELECTOR/private key path or DNS selector before onboarding.',
    },
  });
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
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

module.exports = {
  app,
  normalizeDomain,
  parseConfiguredDomains,
  evaluateDomainReadiness,
  resolveSigningDomain,
  buildDeactivationImpact,
  deactivatedDomains,
  DEACTIVATION_CONFIRMATION_TOKEN,
};
