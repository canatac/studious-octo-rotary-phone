/**
 * DKIM2 Signature Tests
 * Issue #63: DKIM2 signature support — next-gen email signing
 */

const assert = require('assert');

// Test DKIM_ALGORITHMS constants
const { DKIM_ALGORITHMS, generateEd25519KeyPair, resolveDkim2KeyPath } = require('../routes/dkim2');

// Test 1: DKIM_ALGORITHMS constants are correct
assert.strictEqual(DKIM_ALGORITHMS.DKIM1, 'rsa-sha256', 'DKIM1 algorithm should be rsa-sha256');
assert.strictEqual(DKIM_ALGORITHMS.DKIM2, 'ed25519-sha512', 'DKIM2 algorithm should be ed25519-sha512');
console.log('PASS: DKIM_ALGORITHMS constants correct');

// Test 2: Ed25519 key pair generation
const keyPair = generateEd25519KeyPair();
assert.ok(keyPair.privateKey, 'Private key should be generated');
assert.ok(keyPair.privateKey.includes('BEGIN PRIVATE KEY'), 'Private key should be PKCS8 PEM');
assert.ok(keyPair.publicKey, 'Public key should be generated');
assert.ok(keyPair.dnsRecord, 'DNS record should be generated');
assert.ok(keyPair.dnsRecord.startsWith('v=DKIM1; k=ed25519; p='), 'DNS record should have correct format');
assert.ok(keyPair.dnsRecord.length > 30, 'DNS record should contain public key data');
console.log('PASS: Ed25519 key pair generation');

// Test 3: DNS record format validation
const dnsRegex = /^v=DKIM1; k=ed25519; p=[A-Za-z0-9+/=]+$/;
assert.ok(dnsRegex.test(keyPair.dnsRecord), 'DNS record should match DKIM1 ed25519 format');
console.log('PASS: DNS record format valid');

// Test 4: Key path resolution
const keyPath = resolveDkim2KeyPath();
assert.ok(typeof keyPath === 'string', 'Key path should be a string');
assert.ok(keyPath.length > 0, 'Key path should not be empty');
console.log('PASS: Key path resolution');

// Test 5: Public key is valid base64
const pubKeyMatch = keyPair.dnsRecord.match(/p=([A-Za-z0-9+/=]+)/);
assert.ok(pubKeyMatch, 'DNS record should contain p= tag');
const pubKeyBase64 = pubKeyMatch[1];
const pubKeyBuffer = Buffer.from(pubKeyBase64, 'base64');
assert.strictEqual(pubKeyBuffer.length, 32, 'Ed25519 public key should be 32 bytes');
console.log('PASS: Public key is valid 32-byte Ed25519 key');

// Test 6: Key pair is deterministic (different each time)
const keyPair2 = generateEd25519KeyPair();
assert.notStrictEqual(keyPair.privateKey, keyPair2.privateKey, 'Each key pair should be unique');
assert.notStrictEqual(keyPair.publicKey, keyPair2.publicKey, 'Each public key should be unique');
console.log('PASS: Key pairs are unique');

// Test 7: Sign email config selection logic
const { signEmailDkim2 } = require('../routes/dkim2');

(async () => {
    // Test with DKIM2 key available
    const result1 = await signEmailDkim2(
        { from: 'test@example.com', to: 'dest@example.com', subject: 'Test', body: 'Hello' },
        { signingDomain: 'example.com', keySelector: 'default', dkim1Key: 'key1', dkim2Key: 'key2', preferredAlgorithm: 'ed25519-sha512' }
    );
    assert.strictEqual(result1.algorithm, 'ed25519-sha512', 'Should use DKIM2 when key available');
    assert.strictEqual(result1.privateKey, 'key2', 'Should use DKIM2 private key');

    // Test fallback when DKIM2 key unavailable
    const result2 = await signEmailDkim2(
        { from: 'test@example.com', to: 'dest@example.com', subject: 'Test', body: 'Hello' },
        { signingDomain: 'example.com', keySelector: 'default', dkim1Key: 'key1', dkim2Key: null, preferredAlgorithm: 'ed25519-sha512' }
    );
    assert.strictEqual(result2.algorithm, 'rsa-sha256', 'Should fallback to DKIM1 when DKIM2 key unavailable');
    assert.strictEqual(result2.privateKey, 'key1', 'Should use DKIM1 private key on fallback');

    // Test explicit DKIM1 request
    const result3 = await signEmailDkim2(
        { from: 'test@example.com', to: 'dest@example.com', subject: 'Test', body: 'Hello' },
        { signingDomain: 'example.com', keySelector: 'default', dkim1Key: 'key1', dkim2Key: 'key2', preferredAlgorithm: 'rsa-sha256' }
    );
    assert.strictEqual(result3.algorithm, 'rsa-sha256', 'Should respect explicit DKIM1 request');

    console.log('PASS: Sign email config selection logic');
    console.log('\nAll DKIM2 tests passed!');
})().catch(err => {
    console.error('FAIL:', err.message);
    process.exit(1);
});
