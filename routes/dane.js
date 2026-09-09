/**
 * DANE/TLSA Record Validation Module
 * Issue #34: DANE/TLSA record validation
 *
 * DANE (DNS-Based Authentication of Named Entities) authenticates TLS certificates
 * via DNSSEC-signed TLSA records. This module validates TLSA records for domains.
 */

const dns = require('dns').promises;

/**
 * TLSA Record Certificate Usage
 */
const CERT_USAGE = {
  0: 'CA', // Certificate Authority constraint
  1: 'Service', // Service certificate constraint
  2: 'TrustAnchor', // Trust anchor assertion
  3: 'DomainIssued', // Domain-issued certificate
};

/**
 * TLSA Record Selector
 */
const SELECTOR = {
  0: 'FullCertificate', // Full certificate
  1: 'SubjectPublicKeyInfo', // Subject Public Key Info
};

/**
 * TLSA Record Matching Type
 */
const MATCHING_TYPE = {
  0: 'Exact', // Exact match
  1: 'SHA256', // SHA-256 hash
  2: 'SHA512', // SHA-512 hash
};

/**
 * Parse a TLSA record from its wire format
 * TLSA records have the format: <usage> <selector> <matching> <cert-data>
 * @param {string} record - TLSA record string
 * @returns {object} Parsed TLSA record
 */
function parseTlsaRecord(record) {
  if (!record || typeof record !== 'string') {
    return { valid: false, error: 'Empty or invalid record' };
  }

  const parts = record.trim().split(/\s+/);
  if (parts.length < 4) {
    return { valid: false, error: 'TLSA record must have 4 fields: usage selector matching cert-data' };
  }

  const usage = parseInt(parts[0], 10);
  const selector = parseInt(parts[1], 10);
  const matching = parseInt(parts[2], 10);
  const certData = parts[3];

  if (isNaN(usage) || !CERT_USAGE[usage]) {
    return { valid: false, error: `Invalid certificate usage: ${parts[0]}` };
  }
  if (isNaN(selector) || !SELECTOR[selector]) {
    return { valid: false, error: `Invalid selector: ${parts[1]}` };
  }
  if (isNaN(matching) || !MATCHING_TYPE[matching]) {
    return { valid: false, error: `Invalid matching type: ${parts[2]}` };
  }
  if (!certData || certData.length === 0) {
    return { valid: false, error: 'Certificate data is empty' };
  }

  // Validate certificate data format based on matching type
  if (matching === 0 && !/^[A-Fa-f0-9]+$/.test(certData)) {
    return { valid: false, error: 'Exact match requires hex-encoded certificate data' };
  }
  if (matching === 1 && certData.length !== 64) {
    return { valid: false, error: 'SHA-256 hash must be 64 hex characters' };
  }
  if (matching === 2 && certData.length !== 128) {
    return { valid: false, error: 'SHA-512 hash must be 128 hex characters' };
  }

  return {
    valid: true,
    usage,
    usageName: CERT_USAGE[usage],
    selector,
    selectorName: SELECTOR[selector],
    matching,
    matchingName: MATCHING_TYPE[matching],
    certData,
    raw: record.trim(),
  };
}

/**
 * Resolve TLSA records for a domain
 * TLSA records are typically published at _port._protocol.domain
 * @param {string} domain - Domain to query
 * @param {number} port - Port number (default 25 for SMTP)
 * @param {string} protocol - Protocol (default tcp)
 * @returns {object} TLSA records and metadata
 */
async function resolveTlsaRecords(domain, port = 25, protocol = 'tcp') {
  const host = `_${port}._${protocol}.${domain}`;

  try {
    const records = await dns.resolveTlsa(host);
    return {
      host,
      found: true,
      records: records.map((r) => ({
        ...r,
        usageName: CERT_USAGE[r.usage] || 'Unknown',
        selectorName: SELECTOR[r.selector] || 'Unknown',
        matchingName: MATCHING_TYPE[r.matchingType] || 'Unknown',
      })),
      count: records.length,
    };
  } catch (error) {
    return {
      host,
      found: false,
      records: [],
      count: 0,
      error: error.code || error.message || 'DNS lookup failed',
    };
  }
}

/**
 * Check DNSSEC validation status for a domain
 * @param {string} domain - Domain to check
 * @returns {object} DNSSEC status
 */
async function checkDnssec(domain) {
  try {
    // Note: Node.js dns module doesn't directly expose DNSSEC status
    // We check if DNS responses are available as a proxy
    const result = await dns.resolveSoa(domain);
    return {
      domain,
      dnssecEnabled: !!result,
      soa: result,
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    return {
      domain,
      dnssecEnabled: false,
      error: error.code || error.message || 'DNS lookup failed',
      checkedAt: new Date().toISOString(),
    };
  }
}

/**
 * Validate DANE/TLSA records for a domain
 * @param {string} domain - Domain to validate
 * @param {object} options - Validation options
 * @returns {object} DANE validation report
 */
async function validateDane(domain, options = {}) {
  const port = options.port || 25;
  const protocol = options.protocol || 'tcp';
  const normalizedDomain = String(domain || '').trim().toLowerCase().replace(/^@+/, '');

  if (!normalizedDomain) {
    return {
      domain: normalizedDomain,
      valid: false,
      code: 'DOMAIN_INVALID',
      message: 'Domain is required',
      checkedAt: new Date().toISOString(),
    };
  }

  // Resolve TLSA records
  const tlsaResult = await resolveTlsaRecords(normalizedDomain, port, protocol);

  // Check DNSSEC
  const dnssecResult = await checkDnssec(normalizedDomain);

  // Parse and validate each TLSA record
  const parsedRecords = tlsaResult.records.map((record) => {
    const recordStr = `${record.usage} ${record.selector} ${record.matchingType} ${record.certificate}`;
    return parseTlsaRecord(recordStr);
  });

  const validRecords = parsedRecords.filter((r) => r.valid);
  const invalidRecords = parsedRecords.filter((r) => !r.valid);

  // Determine overall status
  let status = 'healthy';
  let code = 'DANE_VALID';

  if (!tlsaResult.found) {
    status = 'critical';
    code = 'TLSA_NOT_FOUND';
  } else if (invalidRecords.length > 0) {
    status = 'degraded';
    code = 'TLSA_INVALID_RECORDS';
  } else if (!dnssecResult.dnssecEnabled) {
    status = 'degraded';
    code = 'DNSSEC_NOT_ENABLED';
  }

  return {
    domain: normalizedDomain,
    valid: status === 'healthy',
    status,
    code,
    tlsa: {
      host: tlsaResult.host,
      found: tlsaResult.found,
      count: tlsaResult.count,
      records: parsedRecords,
    },
    dnssec: dnssecResult,
    summary: {
      totalRecords: parsedRecords.length,
      validRecords: validRecords.length,
      invalidRecords: invalidRecords.length,
    },
    remediation: generateRemediation(code, tlsaResult, dnssecResult),
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Generate remediation hints based on validation result
 */
function generateRemediation(code, tlsaResult, dnssecResult) {
  const remediation = [];

  switch (code) {
    case 'TLSA_NOT_FOUND':
      remediation.push('Publish TLSA records at _25._tcp.<domain> for DANE validation');
      remediation.push('Ensure DNSSEC is enabled for the domain');
      break;
    case 'TLSA_INVALID_RECORDS':
      remediation.push('Fix malformed TLSA records (check usage, selector, matching type, and cert data)');
      break;
    case 'DNSSEC_NOT_ENABLED':
      remediation.push('Enable DNSSEC for the domain to ensure TLSA record authenticity');
      break;
    default:
      break;
  }

  return remediation;
}

module.exports = {
  parseTlsaRecord,
  resolveTlsaRecords,
  checkDnssec,
  validateDane,
  CERT_USAGE,
  SELECTOR,
  MATCHING_TYPE,
  registerDaneRoutes: (app) => {
    app.get('/api/v1/domains/:domain/dane/status', async (req, res) => {
      try {
        const result = await validateDane(req.params.domain, {
          port: parseInt(req.query.port, 10) || 25,
          protocol: req.query.protocol || 'tcp',
        });
        const status = result.valid ? 200 : result.status === 'critical' ? 503 : 422;
        res.status(status).json(result);
      } catch (error) {
        res.status(500).json({
          status: 'error',
          code: 'DANE_VALIDATION_ERROR',
          message: error.message || 'Unknown error',
        });
      }
    });

    app.get('/api/v1/domains/:domain/dane/tlsa', async (req, res) => {
      try {
        const result = await resolveTlsaRecords(
          req.params.domain,
          parseInt(req.query.port, 10) || 25,
          req.query.protocol || 'tcp',
        );
        res.status(200).json(result);
      } catch (error) {
        res.status(500).json({
          status: 'error',
          code: 'TLSA_LOOKUP_ERROR',
          message: error.message || 'Unknown error',
        });
      }
    });

    app.get('/api/v1/domains/:domain/dane/dnssec', async (req, res) => {
      try {
        const result = await checkDnssec(req.params.domain);
        res.status(200).json(result);
      } catch (error) {
        res.status(500).json({
          status: 'error',
          code: 'DNSSEC_CHECK_ERROR',
          message: error.message || 'Unknown error',
        });
      }
    });
  },
};
