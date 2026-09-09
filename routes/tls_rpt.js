/**
 * TLS-RPT (TLS Reporting) Route Module
 * Issue #35: SMTP TLS reporting (TLS-RPT) aggregation
 *
 * TLS-RPT (RFC 8460) allows receiving reports about SMTP TLS connection failures.
 * This module handles report reception, parsing, aggregation, and alerting.
 */

const dns = require('dns').promises;

/**
 * In-memory store for TLS-RPT reports (configurable retention)
 */
const reportStore = [];
const MAX_REPORTS = parseInt(process.env.TLS_RPT_MAX_REPORTS, 10) || 1000;
const FAILURE_THRESHOLD = parseInt(process.env.TLS_RPT_FAILURE_THRESHOLD, 10) || 10;

/**
 * Parse a TLS-RPT report from JSON
 * @param {object} report - Raw TLS-RPT report JSON
 * @returns {object} Parsed and validated report
 */
function parseTlsRptReport(report) {
  if (!report || typeof report !== 'object') {
    return { valid: false, error: 'Report must be a JSON object' };
  }

  if (!report['organization-name']) {
    return { valid: false, error: 'Missing organization-name' };
  }

  if (!report['date-range'] || !report['date-range']['start-datetime'] || !report['date-range']['end-datetime']) {
    return { valid: false, error: 'Missing or invalid date-range' };
  }

  if (!Array.isArray(report['policies']) || report['policies'].length === 0) {
    return { valid: false, error: 'Missing or empty policies array' };
  }

  const policies = report['policies'].map((policy, idx) => {
    if (!policy['policy'] || !policy['policy']['policy-type']) {
      return { valid: false, error: `Policy ${idx} missing policy-type` };
    }

    const failures = (policy['failures'] || []).map((failure) => ({
      'result-type': failure['result-type'] || 'unknown',
      'sending-mta-ip': failure['sending-mta-ip'] || null,
      'receiving-mx-hostname': failure['receiving-mx-hostname'] || null,
      'receiving-mx-helo': failure['receiving-mx-helo'] || null,
      'receiving-ip': failure['receiving-ip'] || null,
      'failed-session-count': parseInt(failure['failed-session-count'], 10) || 0,
      'additional-information': failure['additional-information'] || null,
      'failure-reason-code': failure['failure-reason-code'] || null,
    }));

    const totalFailures = failures.reduce((sum, f) => sum + f['failed-session-count'], 0);
    const totalSuccesses = parseInt(policy['summary']?.['total-successful-session-count'] || 0, 10);
    const totalAttempts = parseInt(policy['summary']?.['total-failure-session-count'] || 0, 10) + totalSuccesses;

    return {
      'policy-type': policy['policy']['policy-type'],
      'policy-domain': policy['policy']['policy-domain'] || null,
      'policy-string': policy['policy']['policy-string'] || [],
      failures,
      summary: {
        totalAttempts,
        totalSuccesses,
        totalFailures,
        failureRate: totalAttempts > 0 ? totalFailures / totalAttempts : 0,
      },
    };
  });

  const invalidPolicy = policies.find((p) => p.valid === false);
  if (invalidPolicy) {
    return { valid: false, error: invalidPolicy.error };
  }

  return {
    valid: true,
    'organization-name': report['organization-name'],
    'date-range': report['date-range'],
    'contact-info': report['contact-info'] || null,
    'report-id': report['report-id'] || `rpt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    policies,
    receivedAt: new Date().toISOString(),
  };
}

/**
 * Store a TLS-RPT report
 * @param {object} report - Parsed report
 */
function storeReport(report) {
  reportStore.push(report);

  // Enforce retention limit
  while (reportStore.length > MAX_REPORTS) {
    reportStore.shift();
  }
}

/**
 * Get all stored reports
 * @returns {Array} Array of reports
 */
function getReports() {
  return [...reportStore];
}

/**
 * Aggregate failures by destination domain
 * @returns {object} Aggregated failure data by domain
 */
function aggregateByDomain() {
  const domainMap = {};

  for (const report of reportStore) {
    for (const policy of report.policies) {
      const domain = policy['policy-domain'];
      if (!domain) continue;

      if (!domainMap[domain]) {
        domainMap[domain] = {
          domain,
          totalAttempts: 0,
          totalSuccesses: 0,
          totalFailures: 0,
          failureReasons: {},
          resultTypes: {},
          reports: 0,
        };
      }

      const agg = domainMap[domain];
      agg.totalAttempts += policy.summary.totalAttempts;
      agg.totalSuccesses += policy.summary.totalSuccesses;
      agg.totalFailures += policy.summary.totalFailures;
      agg.reports += 1;

      for (const failure of policy.failures) {
        const reason = failure['failure-reason-code'] || 'unknown';
        agg.failureReasons[reason] = (agg.failureReasons[reason] || 0) + failure['failed-session-count'];

        const resultType = failure['result-type'];
        agg.resultTypes[resultType] = (agg.resultTypes[resultType] || 0) + failure['failed-session-count'];
      }
    }
  }

  // Calculate failure rates
  for (const domain of Object.keys(domainMap)) {
    const agg = domainMap[domain];
    agg.failureRate = agg.totalAttempts > 0 ? agg.totalFailures / agg.totalAttempts : 0;
  }

  return domainMap;
}

/**
 * Check for alert conditions
 * @returns {Array} Array of alert objects
 */
function checkAlerts() {
  const alerts = [];
  const domainMap = aggregateByDomain();

  for (const domain of Object.keys(domainMap)) {
    const agg = domainMap[domain];

    if (agg.totalFailures >= FAILURE_THRESHOLD) {
      alerts.push({
        type: 'failure_spike',
        severity: agg.failureRate > 0.5 ? 'critical' : 'warning',
        domain,
        totalFailures: agg.totalFailures,
        failureRate: agg.failureRate,
        threshold: FAILURE_THRESHOLD,
        message: `TLS failures for ${domain}: ${agg.totalFailures} failures (${(agg.failureRate * 100).toFixed(1)}% failure rate)`,
        triggeredAt: new Date().toISOString(),
      });
    }
  }

  return alerts;
}

/**
 * Get TLS-RPT statistics
 * @returns {object} Statistics summary
 */
function getStats() {
  const domainMap = aggregateByDomain();
  const domains = Object.values(domainMap);

  return {
    totalReports: reportStore.length,
    totalDomains: domains.length,
    totalFailures: domains.reduce((sum, d) => sum + d.totalFailures, 0),
    totalAttempts: domains.reduce((sum, d) => sum + d.totalAttempts, 0),
    overallFailureRate: domains.reduce((sum, d) => sum + d.totalAttempts, 0) > 0
      ? domains.reduce((sum, d) => sum + d.totalFailures, 0) / domains.reduce((sum, d) => sum + d.totalAttempts, 0)
      : 0,
    alerts: checkAlerts(),
    retentionLimit: MAX_REPORTS,
    failureThreshold: FAILURE_THRESHOLD,
  };
}

/**
 * Register TLS-RPT routes
 * @param {object} app - Express application
 */
function registerTlsRptRoutes(app) {
  // Receive TLS-RPT reports
  app.post('/api/v1/tls-rpt/reports', async (req, res) => {
    try {
      const report = parseTlsRptReport(req.body);

      if (!report.valid) {
        return res.status(400).json({
          status: 'error',
          code: 'INVALID_REPORT',
          message: report.error,
        });
      }

      storeReport(report);

      // Check for alerts
      const alerts = checkAlerts();

      res.status(200).json({
        status: 'success',
        message: 'Report received',
        reportId: report['report-id'],
        alerts,
      });
    } catch (error) {
      res.status(500).json({
        status: 'error',
        code: 'REPORT_PROCESSING_ERROR',
        message: error.message || 'Unknown error',
      });
    }
  });

  // Get all reports
  app.get('/api/v1/tls-rpt/reports', (req, res) => {
    const reports = getReports();
    res.status(200).json({
      count: reports.length,
      reports,
    });
  });

  // Get aggregated statistics
  app.get('/api/v1/tls-rpt/stats', (req, res) => {
    res.status(200).json(getStats());
  });

  // Get aggregated failures by domain
  app.get('/api/v1/tls-rpt/domains', (req, res) => {
    const domainMap = aggregateByDomain();
    res.status(200).json({
      count: Object.keys(domainMap).length,
      domains: Object.values(domainMap),
    });
  });

  // Get alerts
  app.get('/api/v1/tls-rpt/alerts', (req, res) => {
    res.status(200).json({
      count: checkAlerts().length,
      alerts: checkAlerts(),
    });
  });
}

module.exports = {
  parseTlsRptReport,
  storeReport,
  getReports,
  aggregateByDomain,
  checkAlerts,
  getStats,
  registerTlsRptRoutes,
  MAX_REPORTS,
  FAILURE_THRESHOLD,
};
