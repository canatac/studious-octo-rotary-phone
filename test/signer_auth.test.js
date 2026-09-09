const { registerSigningDomainConfigRoutes } = require('../routes/signing_domain_config');

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

// Mock Express app
const createMockApp = () => {
  const routes = {};
  return {
    get: (path, handler) => { routes[`GET ${path}`] = handler; },
    post: (path, handler) => { routes[`POST ${path}`] = handler; },
    routes,
  };
};

// Mock Request
const createMockReq = (overrides = {}) => ({
  path: overrides.path || '/signing-domain-config/export',
  ip: overrides.ip || '127.0.0.1',
  query: overrides.query || {},
  body: overrides.body || {},
  get: (header) => overrides.headers?.[header] || '',
  ...overrides,
});

// Mock Response
const createMockRes = () => {
  const res = {
    statusCode: null,
    jsonBody: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.jsonBody = body;
      return this;
    },
  };
  return res;
};

// Shared state for tests
const createDeps = (token = 'test-secret-token') => {
  let runtimeConfig = {
    schemaVersion: 'v1',
    domainName: 'example.com',
    keySelector: 'default',
    dkimDomains: ['example.com'],
    privateKeyPath: '/tmp/test.key',
  };
  let privateKey = 'test-private-key-material';

  return {
    app: createMockApp(),
    getRuntimeConfig: () => runtimeConfig,
    setRuntimeConfig: (next) => { runtimeConfig = next; },
    getPrivateKey: () => privateKey,
    setPrivateKey: (next) => { privateKey = next; },
    readPrivateKeyFromPath: () => 'fallback-key',
    secureConfigToken: token,
    getRuntimeConfigValue: () => runtimeConfig,
  };
};

console.log('Signer Auth Hardening Tests (Issue #22)');
console.log('========================================\n');

// --- Test 1: Export without auth (public, no secure flag) ---
console.log('Test 1: Export without auth (public, no secure flag)');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];
  const req = createMockReq({ query: {} });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 200, 'Public export returns 200');
  assertEqual(res.jsonBody.config.privateKeyIncluded, false, 'Private key not included in public export');
  assertEqual(res.jsonBody.config.privateKey, undefined, 'Private key value is undefined');
}

// --- Test 2: Export with secure=true but no Bearer token ---
console.log('\nTest 2: Export with secure=true but no Bearer token');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];
  const req = createMockReq({ query: { secure: 'true' } });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 401, 'Secure export without token returns 401');
  assertEqual(res.jsonBody.code, 'AUTH_REQUIRED', 'Error code is AUTH_REQUIRED');
}

// --- Test 3: Export with secure=true and valid Bearer token ---
console.log('\nTest 3: Export with secure=true and valid Bearer token');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];
  const req = createMockReq({
    query: { secure: 'true' },
    headers: { authorization: 'Bearer test-secret-token' },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 200, 'Secure export with valid token returns 200');
  assertEqual(res.jsonBody.config.privateKeyIncluded, true, 'Private key included');
  assertEqual(res.jsonBody.config.privateKey, 'test-private-key-material', 'Private key value present');
}

// --- Test 4: Export with invalid Bearer token ---
console.log('\nTest 4: Export with invalid Bearer token');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];
  const req = createMockReq({
    query: { secure: 'true' },
    headers: { authorization: 'Bearer wrong-token' },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 403, 'Secure export with invalid token returns 403');
  assertEqual(res.jsonBody.code, 'FORBIDDEN', 'Error code is FORBIDDEN');
}

// --- Test 5: Token in query string is REJECTED ---
console.log('\nTest 5: Token in query string is REJECTED');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];
  const req = createMockReq({
    query: { secure: 'true', token: 'test-secret-token' },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 401, 'Token in query string is rejected (401)');
}

// --- Test 6: Token in body is REJECTED ---
console.log('\nTest 6: Token in body is REJECTED');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['POST /signing-domain-config/import'];
  const req = createMockReq({
    path: '/signing-domain-config/import',
    body: {
      token: 'test-secret-token',
      schemaVersion: 'v1',
      config: {
        domainName: 'test.com',
        keySelector: 'default',
        dkimDomains: ['test.com'],
      },
    },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 401, 'Token in body is rejected (401)');
}

// --- Test 7: Import without auth returns 401 ---
console.log('\nTest 7: Import without auth returns 401');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['POST /signing-domain-config/import'];
  const req = createMockReq({
    path: '/signing-domain-config/import',
    body: {
      schemaVersion: 'v1',
      config: {
        domainName: 'test.com',
        keySelector: 'default',
        dkimDomains: ['test.com'],
      },
    },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 401, 'Import without auth returns 401');
  assertEqual(res.jsonBody.code, 'AUTH_REQUIRED', 'Error code is AUTH_REQUIRED');
}

// --- Test 8: Import with valid auth succeeds ---
console.log('\nTest 8: Import with valid auth succeeds');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['POST /signing-domain-config/import'];
  const req = createMockReq({
    path: '/signing-domain-config/import',
    headers: { authorization: 'Bearer test-secret-token' },
    body: {
      schemaVersion: 'v1',
      dryRun: false,
      config: {
        domainName: 'newdomain.com',
        keySelector: 'newselector',
        dkimDomains: ['newdomain.com'],
      },
    },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 200, 'Import with valid auth returns 200');
  assertEqual(res.jsonBody.applied, true, 'Config was applied');
  assertEqual(deps.getRuntimeConfigValue().domainName, 'newdomain.com', 'Runtime config was updated');
}

// --- Test 9: Rate limiting after 10 failed attempts ---
console.log('\nTest 9: Rate limiting after 10 failed attempts');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['GET /signing-domain-config/export'];

  // Make 10 failed attempts
  for (let i = 0; i < 10; i++) {
    const req = createMockReq({
      query: { secure: 'true' },
      headers: { authorization: 'Bearer wrong-token' },
    });
    const res = createMockRes();
    handler(req, res);
  }

  // 11th attempt should be rate limited
  const req = createMockReq({
    query: { secure: 'true' },
    headers: { authorization: 'Bearer wrong-token' },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 429, '11th failed attempt returns 429 (rate limited)');
  assertEqual(res.jsonBody.code, 'RATE_LIMITED', 'Error code is RATE_LIMITED');
}

// --- Test 10: No token configured returns 500 ---
console.log('\nTest 10: No token configured returns 500');
{
  const deps = createDeps(''); // empty token
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['POST /signing-domain-config/import'];
  const req = createMockReq({
    path: '/signing-domain-config/import',
    body: {
      schemaVersion: 'v1',
      config: {
        domainName: 'test.com',
        keySelector: 'default',
        dkimDomains: ['test.com'],
      },
    },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 500, 'No token configured returns 500');
  assertEqual(res.jsonBody.code, 'MISCONFIGURED', 'Error code is MISCONFIGURED');
}

// --- Test 11: Import with secure=true and valid auth + private key ---
console.log('\nTest 11: Import with secure=true and valid auth + private key');
{
  const deps = createDeps();
  registerSigningDomainConfigRoutes(deps);
  const handler = deps.app.routes['POST /signing-domain-config/import'];
  const req = createMockReq({
    path: '/signing-domain-config/import',
    headers: { authorization: 'Bearer test-secret-token' },
    body: {
      schemaVersion: 'v1',
      secure: true,
      dryRun: false,
      config: {
        domainName: 'secure.com',
        keySelector: 'secure',
        dkimDomains: ['secure.com'],
        privateKey: 'super-secret-key',
      },
    },
  });
  const res = createMockRes();
  handler(req, res);
  assertEqual(res.statusCode, 200, 'Secure import with valid auth returns 200');
  assertEqual(res.jsonBody.applied, true, 'Config was applied');
}

// --- Summary ---
console.log('\n========================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
