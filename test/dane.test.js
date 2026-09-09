const {
  parseTlsaRecord,
  CERT_USAGE,
  SELECTOR,
  MATCHING_TYPE,
} = require('../routes/dane');

// Simple test runner
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

console.log('DANE/TLSA Record Validation Tests');
console.log('==================================\n');

console.log('parseTlsaRecord:');

// Valid TLSA records
const validRecord = parseTlsaRecord('3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
assert(validRecord.valid, 'Valid TLSA record (usage=3, selector=1, matching=1)');
assertEqual(validRecord.usage, 3, 'Usage field parsed correctly');
assertEqual(validRecord.usageName, 'DomainIssued', 'Usage name resolved');
assertEqual(validRecord.selector, 1, 'Selector field parsed correctly');
assertEqual(validRecord.selectorName, 'SubjectPublicKeyInfo', 'Selector name resolved');
assertEqual(validRecord.matching, 1, 'Matching field parsed correctly');
assertEqual(validRecord.matchingName, 'SHA256', 'Matching name resolved');

// Valid record with CA usage
const caRecord = parseTlsaRecord('0 0 0 AABBCCDDEEFF');
assert(caRecord.valid, 'Valid CA constraint record (usage=0, selector=0, matching=0)');

// Valid record with TrustAnchor
const taRecord = parseTlsaRecord('2 0 1 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
assert(taRecord.valid, 'Valid TrustAnchor record (usage=2)');

// Invalid records
const emptyRecord = parseTlsaRecord('');
assert(!emptyRecord.valid, 'Empty record is invalid');

const nullRecord = parseTlsaRecord(null);
assert(!nullRecord.valid, 'Null record is invalid');

const shortRecord = parseTlsaRecord('3 1');
assert(!shortRecord.valid, 'Record with <4 fields is invalid');

const invalidUsage = parseTlsaRecord('5 1 1 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
assert(!invalidUsage.valid, 'Invalid usage (5) is rejected');

const invalidSelector = parseTlsaRecord('3 2 1 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
assert(!invalidSelector.valid, 'Invalid selector (2) is rejected');

const invalidMatching = parseTlsaRecord('3 1 3 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
assert(!invalidMatching.valid, 'Invalid matching type (3) is rejected');

const emptyCertData = parseTlsaRecord('3 1 1 ');
assert(!emptyCertData.valid, 'Empty certificate data is rejected');

const wrongSha256Length = parseTlsaRecord('3 1 1 1234567890abcdef');
assert(!wrongSha256Length.valid, 'SHA-256 hash with wrong length is rejected');

const wrongSha512Length = parseTlsaRecord('3 1 2 1234567890abcdef1234567890abcdef');
assert(!wrongSha512Length.valid, 'SHA-512 hash with wrong length is rejected');

const nonHexExact = parseTlsaRecord('3 0 0 GHIJKL');
assert(!nonHexExact.valid, 'Non-hex data for exact match is rejected');

console.log('\nConstants:');
assert(Object.keys(CERT_USAGE).length === 4, 'CERT_USAGE has 4 entries');
assert(Object.keys(SELECTOR).length === 2, 'SELECTOR has 2 entries');
assert(Object.keys(MATCHING_TYPE).length === 3, 'MATCHING_TYPE has 3 entries');

console.log('\n==================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
