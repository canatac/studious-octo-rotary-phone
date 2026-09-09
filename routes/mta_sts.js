/**
 * MTA-STS Policy Enforcement for Outbound SMTP
 * Issue #32: [po] feature: MTA-STS policy enforcement for outbound SMTP
 *
 * Implements RFC 8461 - SMTP MTA Strict Transport Security
 * - Policy publication endpoint
 * - TLS validation for outbound SMTP connections
 * - TLS-RPT report generation
 * - Test mode → Enforce mode progression
 */

const dns = require('dns').promises;

// MTA-STS Policy modes
const POLICY_MODES = {
  TEST: 'test',
  ENFORCE: 'enforce',
  NONE: 'none',
};

// Default policy configuration
const defaultPolicy = {
  mode: POLICY_MODES.TEST, // Start in test mode for validation
  maxAge: 86400, // 24 hours in seconds
  mxHosts: [], // Allowed MX hosts
  tlsrptReportingEmail: '', // Email for TLS-RPT reports
};

let mtaStsConfig = { ...defaultPolicy };

/**
 * Validate TLS connection to remote MX host
 * @param {string} mxHost - MX hostname to validate
 * @param {number} port - SMTP port (default 25)
 * @returns {Promise<object>} - TLS validation result
 */
async function validateTlsConnection(mxHost, port = 25) {
  const tls = require('tls');
  const net = require('net');

  return new Promise((resolve) => {
    const result = {
      host: mxHost,
      port,
      tlsSupported: false,
      certificateValid: false,
      certificate: null,
      error: null,
    };

    const socket = net.connect(port, mxHost, () => {
      const tlsSocket = tls.connect({
        socket,
        servername: mxHost,
        rejectUnauthorized: true,
      }, () => {
        result.tlsSupported = true;
        result.certificateValid = tlsSocket.authorized;
        const cert = tlsSocket.getPeerCertificate();
        result.certificate = {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          fingerprint: cert.fingerprint,
        };
        tlsSocket.end();
        resolve(result);
      });

      tlsSocket.on('error', (err) => {
        result.error = err.message;
        tlsSocket.destroy();
        resolve(result);
      });
    });

    socket.on('error', (err) => {
      result.error = err.message;
      socket.destroy();
      resolve(result);
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      result.error = 'Connection timeout';
      socket.destroy();
      resolve(result);
    }, 10000);
  });
}

/**
 * Validate outbound SMTP connection against MTA-STS policy
 * @param {string} destinationDomain - Destination domain
 * @param {string} mxHost - MX host to connect to
 * @returns {Promise<object>} - Validation result
 */
async function validateOutboundWithPolicy(destinationDomain, mxHost) {
  const result = {
    destinationDomain,
    mxHost,
    policyMode: mtaStsConfig.mode,
    allowed: false,
    tlsValid: false,
    errors: [],
  };

  // Check if MX host is in allowed list (enforce mode)
  if (mtaStsConfig.mode === POLICY_MODES.ENFORCE) {
    const normalizedMx = mxHost.toLowerCase();
    const allowedHosts = mtaStsConfig.mxHosts.map(h => h.toLowerCase());
    if (!allowedHosts.includes(normalizedMx) && allowedHosts.length > 0) {
      result.errors.push(`MX host ${mxHost} not in allowed MTA-STS policy`);
      return result;
    }
  }

  // Validate TLS connection
  const tlsResult = await validateTlsConnection(mxHost);
  result.tlsValid = tlsResult.tlsSupported && tlsResult.certificateValid;
  result.tlsDetails = tlsResult;

  if (!tlsResult.tlsSupported) {
    result.errors.push('TLS not supported by remote MX');
  } else if (!tlsResult.certificateValid) {
    result.errors.push(`TLS certificate invalid: ${tlsResult.error}`);
  }

  // In enforce mode, TLS is mandatory
  if (mtaStsConfig.mode === POLICY_MODES.ENFORCE && !result.tlsValid) {
    result.allowed = false;
    result.errors.push('MTA-STS enforce mode: TLS required but failed');
  } else {
    result.allowed = true;
  }

  return result;
}

/**
 * Generate TLS-RPT report
 * @param {object} validationResult - Result from validateOutboundWithPolicy
 * @returns {object} - TLS-RPT report
 */
function generateTlsRptReport(validationResult) {
  const now = new Date();
  return {
    'version': 'STSv1',
    'date-range': {
      'start-datetime': now.toISOString(),
      'end-datetime': now.toISOString(),
    },
    'policy': {
      'policy-type': mtaStsConfig.mode === POLICY_MODES.NONE ? 'none' : 'sts',
      'policy-domain': validationResult.destinationDomain,
      'mx-host': validationResult.mxHost,
      'policy-max-age': mtaStsConfig.maxAge,
    },
    'summary': {
      'total-successful-session-count': validationResult.allowed ? 1 : 0,
      'total-failure-session-count': validationResult.allowed ? 0 : 1,
    },
    'failure-details': validationResult.errors.map((error, index) => ({
      'result-type': validationResult.tlsValid ? 'certificate-expired' : 'starttls-not-supported',
      'sending-mta-ip': '0.0.0.0',
      'receiving-mx-hostname': validationResult.mxHost,
      'receiving-mx-helo': validationResult.mxHost,
      'receiving-ip': '0.0.0.0',
      'failed-session-count': 1,
      'additional-information': error,
    })),
  };
}

/**
 * Register MTA-STS routes
 * @param {object} app - Express application
 */
function registerMtaStsRoutes(app) {
  // GET /.well-known/mta-sts.txt - MTA-STS Policy publication
  app.get('/.well-known/mta-sts.txt', (req, res) => {
    if (mtaStsConfig.mode === POLICY_MODES.NONE) {
      res.status(404).send('MTA-STS policy not configured');
      return;
    }

    const policy = [
      'version: STSv1',
      `mode: ${mtaStsConfig.mode}`,
      ...mtaStsConfig.mxHosts.map(mx => `mx: ${mx}`),
      `max_age: ${mtaStsConfig.maxAge}`,
    ].join('\n');

    res.set('Content-Type', 'text/plain');
    res.status(200).send(policy);
  });

  // GET /mta-sts/policy - Get current policy configuration
  app.get('/mta-sts/policy', (req, res) => {
    res.status(200).json({
      status: 'success',
      policy: mtaStsConfig,
    });
  });

  // PUT /mta-sts/policy - Update policy configuration
  app.put('/mta-sts/policy', (req, res) => {
    const { mode, maxAge, mxHosts, tlsrptReportingEmail } = req.body;

    if (mode && !Object.values(POLICY_MODES).includes(mode)) {
      res.status(400).json({
        status: 'error',
        message: `Invalid mode. Must be one of: ${Object.values(POLICY_MODES).join(', ')}`,
      });
      return;
    }

    if (mode) mtaStsConfig.mode = mode;
    if (maxAge) mtaStsConfig.maxAge = maxAge;
    if (mxHosts) mtaStsConfig.mxHosts = mxHosts;
    if (tlsrptReportingEmail) mtaStsConfig.tlsrptReportingEmail = tlsrptReportingEmail;

    res.status(200).json({
      status: 'success',
      message: 'MTA-STS policy updated',
      policy: mtaStsConfig,
    });
  });

  // POST /mta-sts/validate - Validate outbound SMTP against policy
  app.post('/mta-sts/validate', async (req, res) => {
    const { destinationDomain, mxHost } = req.body;

    if (!destinationDomain || !mxHost) {
      res.status(400).json({
        status: 'error',
        message: 'destinationDomain and mxHost are required',
      });
      return;
    }

    try {
      const result = await validateOutboundWithPolicy(destinationDomain, mxHost);
      res.status(result.allowed ? 200 : 422).json({
        status: result.allowed ? 'valid' : 'invalid',
        result,
      });
    } catch (error) {
      res.status(500).json({
        status: 'error',
        message: error.message,
      });
    }
  });

  // GET /mta-sts/reports - Get TLS-RPT reports
  app.get('/mta-sts/reports', (req, res) => {
    // In production, this would fetch from a database
    res.status(200).json({
      status: 'success',
      reports: [],
      reportingEmail: mtaStsConfig.tlsrptReportingEmail,
    });
  });

  // POST /mta-sts/reports/generate - Generate TLS-RPT report
  app.post('/mta-sts/reports/generate', async (req, res) => {
    const { destinationDomain, mxHost } = req.body;

    if (!destinationDomain || !mxHost) {
      res.status(400).json({
        status: 'error',
        message: 'destinationDomain and mxHost are required',
      });
      return;
    }

    try {
      const validationResult = await validateOutboundWithPolicy(destinationDomain, mxHost);
      const report = generateTlsRptReport(validationResult);
      res.status(200).json({
        status: 'success',
        report,
      });
    } catch (error) {
      res.status(500).json({
        status: 'error',
        message: error.message,
      });
    }
  });
}

module.exports = {
  registerMtaStsRoutes,
  validateOutboundWithPolicy,
  validateTlsConnection,
  generateTlsRptReport,
  POLICY_MODES,
  getMtaStsConfig: () => mtaStsConfig,
  setMtaStsConfig: (config) => { mtaStsConfig = config; },
};
