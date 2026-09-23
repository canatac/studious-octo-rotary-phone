/**
 * Masked Email Alias API Tests
 * Issue #54: Masked email alias management API
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Use a test data directory before importing alias-store
const TEST_DATA_DIR = path.join(__dirname, '..', 'data', 'test-aliases');
process.env.ALIAS_DATA_DIR = TEST_DATA_DIR;

const aliasStore = require('../lib/alias-store');
const { resolveAliasRecipient, recordAliasForward } = require('../routes/alias');

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

// Clean up before tests
if (fs.existsSync(TEST_DATA_DIR)) {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
}

console.log('Masked Email Alias API Tests');
console.log('============================\n');

const userId = 'user-test-123';
const userId2 = 'user-test-456';

// --- createAlias ---
test('createAlias: should create alias with random prefix', () => {
  const record = aliasStore.createAlias(userId, 'misfits.ai', 'test-label');
  assert.ok(record.id, 'should have id');
  assert.ok(record.alias.endsWith('@misfits.ai'), 'should end with @misfits.ai');
  assert.strictEqual(record.userId, userId);
  assert.strictEqual(record.label, 'test-label');
  assert.strictEqual(record.active, true);
  assert.strictEqual(record.forwardedCount, 0);
});

test('createAlias: should generate unique aliases', () => {
  const a1 = aliasStore.createAlias(userId2, 'misfits.ai');
  const a2 = aliasStore.createAlias(userId2, 'misfits.ai');
  assert.notStrictEqual(a1.alias, a2.alias, 'aliases should be unique');
  assert.notStrictEqual(a1.id, a2.id, 'ids should be unique');
});

// --- getAlias ---
test('getAlias: should retrieve existing alias', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const found = aliasStore.getAlias(created.id);
  assert.ok(found, 'should find alias');
  assert.strictEqual(found.id, created.id);
});

test('getAlias: should return null for non-existent', () => {
  const found = aliasStore.getAlias('nonexistent');
  assert.strictEqual(found, null);
});

// --- listAliases ---
test('listAliases: should list user aliases sorted by createdAt desc', () => {
  const aliases = aliasStore.listAliases(userId2);
  assert.ok(aliases.length >= 2, 'should have at least 2 aliases');
  // Verify sorting (descending)
  for (let i = 1; i < aliases.length; i++) {
    assert.ok(
      new Date(aliases[i - 1].createdAt) >= new Date(aliases[i].createdAt),
      'should be sorted descending'
    );
  }
});

test('listAliases: should return empty for unknown user', () => {
  const aliases = aliasStore.listAliases('unknown-user');
  assert.strictEqual(aliases.length, 0);
});

// --- deactivateAlias ---
test('deactivateAlias: should deactivate an alias', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const deactivated = aliasStore.deactivateAlias(created.id, userId);
  assert.strictEqual(deactivated.active, false);
  assert.ok(deactivated.deactivatedAt, 'should have deactivatedAt timestamp');
});

test('deactivateAlias: should return forbidden for wrong user', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const result = aliasStore.deactivateAlias(created.id, userId2);
  assert.strictEqual(result.error, 'forbidden');
});

test('deactivateAlias: should return null for non-existent', () => {
  const result = aliasStore.deactivateAlias('nonexistent', userId);
  assert.strictEqual(result, null);
});

// --- deleteAlias ---
test('deleteAlias: should permanently delete an alias', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const deleted = aliasStore.deleteAlias(created.id, userId);
  assert.strictEqual(deleted, true);
  assert.strictEqual(aliasStore.getAlias(created.id), null);
});

test('deleteAlias: should return false for wrong user', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const result = aliasStore.deleteAlias(created.id, userId2);
  assert.strictEqual(result, false);
});

// --- recordForward ---
test('recordForward: should increment forwarded count', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  aliasStore.recordForward(created.id);
  aliasStore.recordForward(created.id);
  aliasStore.recordForward(created.id);
  const updated = aliasStore.getAlias(created.id);
  assert.strictEqual(updated.forwardedCount, 3);
  assert.ok(updated.lastForwardedAt, 'should have lastForwardedAt');
});

// --- findByAlias ---
test('findByAlias: should find active alias by email', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const found = aliasStore.findByAlias(created.alias);
  assert.ok(found, 'should find alias');
  assert.strictEqual(found.id, created.id);
});

test('findByAlias: should not find deactivated alias', () => {
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  aliasStore.deactivateAlias(created.id, userId);
  const found = aliasStore.findByAlias(created.alias);
  assert.strictEqual(found, null, 'deactivated alias should not be found');
});

test('findByAlias: should return null for unknown email', () => {
  const found = aliasStore.findByAlias('unknown@misfits.ai');
  assert.strictEqual(found, null);
});

// --- getUserAliasCount ---
test('getUserAliasCount: should count only active aliases', () => {
  const before = aliasStore.getUserAliasCount(userId);
  const created = aliasStore.createAlias(userId, 'misfits.ai');
  const after = aliasStore.getUserAliasCount(userId);
  assert.strictEqual(after, before + 1, 'count should increase by 1');
  aliasStore.deactivateAlias(created.id, userId);
  const afterDeactivate = aliasStore.getUserAliasCount(userId);
  assert.strictEqual(afterDeactivate, before, 'count should return to before after deactivation');
});

// --- resolveAliasRecipient (route helper) ---
test('resolveAliasRecipient: should resolve active alias to user', () => {
  const created = aliasStore.createAlias(userId2, 'misfits.ai');
  const resolved = resolveAliasRecipient(created.alias);
  assert.ok(resolved, 'should resolve');
  assert.strictEqual(resolved.userId, userId2);
  assert.strictEqual(resolved.aliasId, created.id);
});

test('resolveAliasRecipient: should return null for non-alias', () => {
  const resolved = resolveAliasRecipient('nobody@misfits.ai');
  assert.strictEqual(resolved, null);
});

// --- Persistence ---
test('persistence: should persist to disk and reload', () => {
  // Create an alias
  const created = aliasStore.createAlias(userId, 'misfits.ai', 'persist-test');
  // Verify file exists
  const storeFile = path.join(TEST_DATA_DIR, 'aliases.json');
  assert.ok(fs.existsSync(storeFile), 'store file should exist');
  // Verify file contains the alias
  const data = JSON.parse(fs.readFileSync(storeFile, 'utf8'));
  assert.ok(data[created.id], 'alias should be in store file');
});

// Summary
console.log(`\nResults: ${passed} passed, ${failed} failed`);

// Clean up test data
if (fs.existsSync(TEST_DATA_DIR)) {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
}

if (failed > 0) {
  process.exit(1);
}
