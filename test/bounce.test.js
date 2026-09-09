const assert = require('assert');
const {
  classifyBounce,
  parseDSN,
  recordBounce,
  getBounceStats,
  getAlerts,
  clearAlerts,
  BOUNCE_CATEGORIES,
} = require('../routes/bounce');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    failed++;
    console.error(`  FAIL: ${name} - ${e.message}`);
  }
}

console.log('Bounce Classification and Handling Tests');
console.log('========================================\n');

// --- classifyBounce ---

test('classifies user unknown as hard bounce', () => {
  const result = classifyBounce('550 5.1.1 User unknown');
  assert.strictEqual(result.category, 'hard');
  assert.strictEqual(result.type, 'hard');
});

test('classifies mailbox not found as hard bounce', () => {
  const result = classifyBounce('550 5.1.10 Mailbox not found');
  assert.strictEqual(result.category, 'hard');
});

test('classifies account disabled as hard bounce', () => {
  const result = classifyBounce('550 5.7.1 Account disabled');
  assert.strictEqual(result.category, 'hard');
});

test('classifies mailbox full as soft bounce', () => {
  const result = classifyBounce('450 4.2.2 Mailbox full');
  assert.strictEqual(result.category, 'soft');
});

test('classifies quota exceeded as soft bounce', () => {
  const result = classifyBounce('450 4.2.2 Quota exceeded');
  assert.strictEqual(result.category, 'soft');
});

test('classifies temporary failure as soft bounce', () => {
  const result = classifyBounce('451 4.3.0 Temporary failure, try again');
  assert.strictEqual(result.category, 'soft');
});

test('classifies abuse as complaint', () => {
  const result = classifyBounce('Abuse report - spam detected');
  assert.strictEqual(result.category, 'complaint');
});

test('classifies spam as complaint', () => {
  const result = classifyBounce('Junk mail complaint');
  assert.strictEqual(result.category, 'complaint');
});

test('classifies unsubscribe as complaint', () => {
  const result = classifyBounce('User opt-out request');
  assert.strictEqual(result.category, 'complaint');
});

test('classifies unknown message as unknown', () => {
  const result = classifyBounce('Some random message');
  assert.strictEqual(result.category, 'unknown');
});

test('classifies empty string as unknown', () => {
  const result = classifyBounce('');
  assert.strictEqual(result.category, 'unknown');
});

test('classifies null as unknown', () => {
  const result = classifyBounce(null);
  assert.strictEqual(result.category, 'unknown');
});

// --- parseDSN ---

test('parses DSN action failed', () => {
  const result = parseDSN('Action: failed\nDiagnostic-Code: 5.1.1');
  assert.strictEqual(result.action, 'failed');
});

test('parses DSN status', () => {
  const result = parseDSN('Status: 5.1.1\nAction: failed');
  assert.strictEqual(result.status, '5.1.1');
});

test('parses DSN diagnostic code', () => {
  const result = parseDSN('Diagnostic-Code: smtp; 550 User unknown');
  assert.strictEqual(result.diagnosticCode, 'smtp; 550 User unknown');
});

test('parses DSN remote MTA', () => {
  const result = parseDSN('Remote-MTA: mx.example.com');
  assert.strictEqual(result.remoteMta, 'mx.example.com');
});

// --- recordBounce ---

test('records a bounce for an email', () => {
  const result = recordBounce('test@example.com', 'hard');
  assert.strictEqual(result.recorded, true);
  assert.strictEqual(result.record.hard, 1);
  assert.strictEqual(result.record.total, 1);
});

test('returns false for empty email', () => {
  const result = recordBounce('', 'hard');
  assert.strictEqual(result.recorded, false);
});

test('detects bounce spike', () => {
  const email = 'spike-test@example.com';
  clearAlerts();
  // Set spike threshold low for testing
  process.env.BOUNCE_SPIKE_THRESHOLD = '3';
  for (let i = 0; i < 3; i++) {
    recordBounce(email, 'hard');
  }
  const stats = getBounceStats(email);
  assert.strictEqual(stats.total, 3);
  const alerts = getAlerts();
  assert.ok(alerts.length > 0, 'Should have generated an alert');
  delete process.env.BOUNCE_SPIKE_THRESHOLD;
});

test('getBounceStats returns null for unknown email', () => {
  const stats = getBounceStats('unknown@test.com');
  assert.strictEqual(stats, null);
});

// --- summary ---

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
