const {
  parseTlsRptReport,
  storeReport,
  getReports,
  aggregateByDomain,
  checkAlerts,
  getStats,
  MAX_REPORTS,
  FAILURE_THRESHOLD,
} = require('../routes/tls_rpt');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${message}`);
  } else {
    failed++;
    console.error(`  FAIL: ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    passed++;
    console.log(`  PASS: ${message}`);
  } else {
    failed++;
    console.error(`  FAIL: ${message} (expected ${expected}, got ${actual})`);
  }
}

console.log('TLS-RPT Report Tests');
console.log('====================\n');

console.log('parseTlsRptReport:');

// Valid report
const validReport = parseTlsRptReport({
  'organization-name': 'Example Corp',
  'date-range': {
    'start-datetime': '2026-09-01T00:00:00Z',
    'end-datetime': '2026-09-02T00:00:00Z',
  },
  'policies': [
    {
      'policy': {
        'policy-type': 'sts',
        'policy-domain': 'example.com',
      },
      'summary': {
        'total-successful-session-count': 100,
        'total-failure-session-count': 5,
      },
      'failures': [
        {
          'result-type': 'certificate-expired',
          'receiving-mx-hostname': 'mail.example.com',
          'failed-session-count': 3,
          'failure-reason-code': 'X.509 certificate expired',
        },
      ],
    },
  ],
});

assert(validReport.valid, 'Valid TLS-RPT report parses correctly');
assertEqual(validReport['organization-name'], 'Example Corp', 'Organization name parsed');
assertEqual(validReport.policies.length, 1, 'One policy parsed');
assertEqual(validReport.policies[0].failures.length, 1, 'One failure parsed');
assertEqual(validReport.policies[0].summary.totalFailures, 5, 'Total failures calculated');
assertEqual(validReport.policies[0].summary.totalSuccesses, 100, 'Total successes parsed');

// Invalid reports
assert(!parseTlsRptReport(null).valid, 'Null report is invalid');
assert(!parseTlsRptReport({}).valid, 'Empty object is invalid');
assert(!parseTlsRptReport({ 'organization-name': 'Test' }).valid, 'Missing date-range is invalid');
assert(!parseTlsRptReport({ 'date-range': {} }).valid, 'Missing organization-name is invalid');
assert(!parseTlsRptReport({ 'organization-name': 'Test', 'date-range': {} }).valid, 'Empty date-range is invalid');
assert(!parseTlsRptReport({ 'organization-name': 'Test', 'date-range': { 'start-datetime': 'x', 'end-datetime': 'y' } }).valid, 'Missing policies is invalid');
assert(!parseTlsRptReport({ 'organization-name': 'Test', 'date-range': { 'start-datetime': 'x', 'end-datetime': 'y' }, 'policies': [] }).valid, 'Empty policies array is invalid');

console.log('\nstoreReport and getReports:');

// Clear existing reports
while (getReports().length > 0) {
  getReports().pop();
}

const report1 = parseTlsRptReport({
  'organization-name': 'Org1',
  'date-range': { 'start-datetime': '2026-09-01T00:00:00Z', 'end-datetime': '2026-09-02T00:00:00Z' },
  'policies': [{ 'policy': { 'policy-type': 'sts', 'policy-domain': 'org1.com' }, 'summary': { 'total-successful-session-count': 50, 'total-failure-session-count': 2 } }],
});

storeReport(report1);
assertEqual(getReports().length, 1, 'Report stored successfully');

const report2 = parseTlsRptReport({
  'organization-name': 'Org2',
  'date-range': { 'start-datetime': '2026-09-02T00:00:00Z', 'end-datetime': '2026-09-03T00:00:00Z' },
  'policies': [{ 'policy': { 'policy-type': 'sts', 'policy-domain': 'org2.com' }, 'summary': { 'total-successful-session-count': 200, 'total-failure-count': 15 } }],
});

storeReport(report2);
assertEqual(getReports().length, 2, 'Second report stored');

console.log('\naggregateByDomain:');

const domainMap = aggregateByDomain();
assert(domainMap['org1.com'], 'org1.com present in aggregation');
assert(domainMap['org2.com'], 'org2.com present in aggregation');
assertEqual(domainMap['org1.com'].totalFailures, 2, 'org1.com has 2 failures');
assertEqual(domainMap['org2.com'].totalFailures, 0, 'org2.com has 0 failures (no failures array)');

console.log('\ncheckAlerts:');

// Add a report with high failures to trigger alert
storeReport(parseTlsRptReport({
  'organization-name': 'AlertOrg',
  'date-range': { 'start-datetime': '2026-09-03T00:00:00Z', 'end-datetime': '2026-09-04T00:00:00Z' },
  'policies': [{
    'policy': { 'policy-type': 'sts', 'policy-domain': 'alert.com' },
    'summary': { 'total-successful-session-count': 100, 'total-failure-session-count': 20 },
    'failures': [{ 'result-type': 'certificate-expired', 'failed-session-count': 20, 'failure-reason-code': 'expired' }],
  }],
}));

const alerts = checkAlerts();
assert(alerts.length > 0, 'Alerts triggered for high failure domain');
const alertDomain = alerts.find(a => a.domain === 'alert.com');
assert(alertDomain, 'Alert for alert.com domain');
assertEqual(alertDomain.totalFailures, 20, 'Alert shows correct failure count');

console.log('\ngetStats:');

const stats = getStats();
assert(stats.totalReports >= 3, 'Stats shows correct report count');
assert(stats.totalDomains >= 3, 'Stats shows correct domain count');
assert(stats.alerts.length > 0, 'Stats includes alerts');

console.log('\nConstants:');
assert(MAX_REPORTS > 0, 'MAX_REPORTS is positive');
assert(FAILURE_THRESHOLD > 0, 'FAILURE_THRESHOLD is positive');

console.log('\n====================');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
