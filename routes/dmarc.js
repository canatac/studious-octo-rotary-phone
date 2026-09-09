/**
 * DMARC Aggregate Report Parsing
 * Issue #36: [po] feature: DMARC aggregate report parsing
 *
 * Parses DMARC aggregate reports (RUA) in XML format.
 * Extracts SPF/DKIM results by source IP, calculates authentication rates.
 */

const xml2js = require('xml-js');

/**
 * Parse DMARC aggregate report XML into structured data
 * @param {string} xmlContent - Raw XML content of the DMARC report
 * @returns {object} - Parsed report data
 */
function parseDmarcXml(xmlContent) {
  const result = xml2js.xml2js(xmlContent, { compact: true, spaces: 2 });
  const report = result.feedback || result;

  const metadata = report.report_metadata || {};
  const policy = report.policy_published || {};

  const parsed = {
    metadata: {
      orgName: getText(metadata.org_name),
      email: getText(metadata.email),
      reportId: getText(metadata.report_id),
      dateRange: {
        begin: getText(metadata.date_range?.begin),
        end: getText(metadata.date_range?.end),
      },
    },
    policy: {
      domain: getText(policy.domain),
      adkim: getText(policy.adkim),
      aspf: getText(policy.aspf),
      p: getText(policy.p),
      sp: getText(policy.sp),
      pct: getText(policy.pct),
    },
    records: [],
    summary: {
      totalRecords: 0,
      passCount: 0,
      failCount: 0,
      dkimPass: 0,
      dkimFail: 0,
      spfPass: 0,
      spfFail: 0,
    },
  };

  const records = report.record ? (Array.isArray(report.record) ? report.record : [report.record]) : [];

  for (const record of records) {
    const row = record.row || {};
    const sourceIp = getText(row.source_ip);
    const count = parseInt(getText(row.count), 10) || 0;

    const policyEvaluated = record.policy_evaluated || {};
    const disposition = getText(policyEvaluated.disposition);
    const dkimResult = getText(policyEvaluated.dkim);
    const spfResult = getText(policyEvaluated.spf);

    const authResults = record.auth_results || {};
    const dkimAuth = authResults.dkim ? (Array.isArray(authResults.dkim) ? authResults.dkim : [authResults.dkim]) : [];
    const spfAuth = authResults.spf ? (Array.isArray(authResults.spf) ? authResults.spf : [authResults.spf]) : [];

    const recordData = {
      sourceIp,
      count,
      disposition,
      dkimResult,
      spfResult,
      dkimDetails: dkimAuth.map(d => ({
        domain: getText(d.domain),
        result: getText(d.result),
        selector: getText(d.selector),
      })),
      spfDetails: spfAuth.map(s => ({
        domain: getText(s.domain),
        result: getText(s.result),
        scope: getText(s.scope),
      })),
    };

    parsed.records.push(recordData);
    parsed.summary.totalRecords += count;

    if (dkimResult === 'pass') {
      parsed.summary.dkimPass += count;
    } else {
      parsed.summary.dkimFail += count;
    }

    if (spfResult === 'pass') {
      parsed.summary.spfPass += count;
    } else {
      parsed.summary.spfFail += count;
    }

    if (dkimResult === 'pass' && spfResult === 'pass') {
      parsed.summary.passCount += count;
    } else {
      parsed.summary.failCount += count;
    }
  }

  // Calculate rates
  parsed.summary.dkimRate = parsed.summary.totalRecords > 0
    ? ((parsed.summary.dkimPass / parsed.summary.totalRecords) * 100).toFixed(2)
    : 0;
  parsed.summary.spfRate = parsed.summary.totalRecords > 0
    ? ((parsed.summary.spfPass / parsed.summary.totalRecords) * 100).toFixed(2)
    : 0;
  parsed.summary.overallRate = parsed.summary.totalRecords > 0
    ? ((parsed.summary.passCount / parsed.summary.totalRecords) * 100).toFixed(2)
    : 0;

  return parsed;
}

/**
 * Get text content from a JS object (handles _text property from xml2js)
 */
function getText(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'object' && value._text) return value._text;
  if (typeof value === 'object' && value._cdata) return value._cdata;
  return String(value);
}

/**
 * Aggregate reports by source IP
 * @param {Array} records - Parsed DMARC records
 * @returns {object} - Aggregated by IP
 */
function aggregateBySource(records) {
  const aggregation = {};

  for (const record of records) {
    const ip = record.sourceIp;
    if (!aggregation[ip]) {
      aggregation[ip] = {
        sourceIp: ip,
        totalCount: 0,
        dkimPass: 0,
        dkimFail: 0,
        spfPass: 0,
        spfFail: 0,
        passCount: 0,
        failCount: 0,
      };
    }

    aggregation[ip].totalCount += record.count;
    aggregation[ip].dkimPass += record.dkimResult === 'pass' ? record.count : 0;
    aggregation[ip].dkimFail += record.dkimResult !== 'pass' ? record.count : 0;
    aggregation[ip].spfPass += record.spfResult === 'pass' ? record.count : 0;
    aggregation[ip].spfFail += record.spfResult !== 'pass' ? record.count : 0;
    aggregation[ip].passCount += (record.dkimResult === 'pass' && record.spfResult === 'pass') ? record.count : 0;
    aggregation[ip].failCount += (record.dkimResult !== 'pass' || record.spfResult !== 'pass') ? record.count : 0;
  }

  return Object.values(aggregation);
}

/**
 * Calculate trends from multiple reports
 * @param {Array} reports - Array of parsed reports
 * @returns {object} - Trend data
 */
function calculateTrends(reports) {
  const sorted = reports.sort((a, b) => {
    const dateA = new Date(a.metadata.dateRange.begin);
    const dateB = new Date(b.metadata.dateRange.begin);
    return dateA - dateB;
  });

  const daily = sorted.map(report => ({
    date: report.metadata.dateRange.begin,
    totalRecords: report.summary.totalRecords,
    passRate: parseFloat(report.summary.overallRate),
    dkimRate: parseFloat(report.summary.dkimRate),
    spfRate: parseFloat(report.summary.spfRate),
  }));

  // Calculate 7/30/90 day averages
  const avg = (arr, days) => {
    const recent = arr.slice(-days);
    if (recent.length === 0) return 0;
    return (recent.reduce((sum, d) => sum + d.passRate, 0) / recent.length).toFixed(2);
  };

  return {
    daily,
    averages: {
      '7d': avg(daily, 7),
      '30d': avg(daily, 30),
      '90d': avg(daily, 90),
    },
  };
}

// In-memory storage for reports (in production, use MongoDB)
const dmarcReports = [];

/**
 * Register DMARC routes
 * @param {object} app - Express application
 */
function registerDmarcRoutes(app) {
  // POST /api/v1/dmarc/reports - Import DMARC aggregate report
  app.post('/api/v1/dmarc/reports', express.json({ limit: '10mb' }), (req, res) => {
    const { xml } = req.body;

    if (!xml) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing XML content. Send raw XML in "xml" field.',
      });
    }

    try {
      const parsed = parseDmarcXml(xml);
      const reportEntry = {
        id: parsed.metadata.reportId || `report-${Date.now()}`,
        importedAt: new Date().toISOString(),
        report: parsed,
      };
      dmarcReports.push(reportEntry);

      res.status(201).json({
        status: 'success',
        message: 'DMARC report imported successfully',
        reportId: reportEntry.id,
        summary: parsed.summary,
      });
    } catch (error) {
      res.status(400).json({
        status: 'error',
        message: 'Failed to parse DMARC XML report',
        detail: error.message,
      });
    }
  });

  // GET /api/v1/dmarc/reports - List all imported reports
  app.get('/api/v1/dmarc/reports', (req, res) => {
    const reports = dmarcReports.map(r => ({
      id: r.id,
      importedAt: r.importedAt,
      metadata: r.report.metadata,
      summary: r.report.summary,
    }));

    res.status(200).json({
      status: 'success',
      count: reports.length,
      reports,
    });
  });

  // GET /api/v1/dmarc/reports/:id - Get specific report details
  app.get('/api/v1/dmarc/reports/:id', (req, res) => {
    const report = dmarcReports.find(r => r.id === req.params.id);
    if (!report) {
      return res.status(404).json({
        status: 'error',
        message: 'Report not found',
      });
    }

    res.status(200).json({
      status: 'success',
      report,
    });
  });

  // GET /api/v1/dmarc/aggregate - Get aggregated data by source IP
  app.get('/api/v1/dmarc/aggregate', (req, res) => {
    const allRecords = dmarcReports.flatMap(r => r.report.records);
    const aggregated = aggregateBySource(allRecords);

    res.status(200).json({
      status: 'success',
      count: aggregated.length,
      sources: aggregated,
    });
  });

  // GET /api/v1/dmarc/trends - Get authentication rate trends
  app.get('/api/v1/dmarc/trends', (req, res) => {
    const reports = dmarcReports.map(r => r.report);
    const trends = calculateTrends(reports);

    res.status(200).json({
      status: 'success',
      trends,
    });
  });

  // GET /api/v1/dmarc/summary - Get overall summary
  app.get('/api/v1/dmarc/summary', (req, res) => {
    const totalRecords = dmarcReports.reduce((sum, r) => sum + r.report.summary.totalRecords, 0);
    const totalPass = dmarcReports.reduce((sum, r) => sum + r.report.summary.passCount, 0);
    const totalDkimPass = dmarcReports.reduce((sum, r) => sum + r.report.summary.dkimPass, 0);
    const totalSpfPass = dmarcReports.reduce((sum, r) => sum + r.report.summary.spfPass, 0);

    res.status(200).json({
      status: 'success',
      summary: {
        totalReports: dmarcReports.length,
        totalRecords,
        totalPass,
        totalFail: totalRecords - totalPass,
        overallRate: totalRecords > 0 ? ((totalPass / totalRecords) * 100).toFixed(2) : 0,
        dkimRate: totalRecords > 0 ? ((totalDkimPass / totalRecords) * 100).toFixed(2) : 0,
        spfRate: totalRecords > 0 ? ((totalSpfPass / totalRecords) * 100).toFixed(2) : 0,
      },
    });
  });
}

module.exports = {
  registerDmarcRoutes,
  parseDmarcXml,
  aggregateBySource,
  calculateTrends,
};
