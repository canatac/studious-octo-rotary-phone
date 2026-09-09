const registerSigningDomainConfigRoutes = ({
  app,
  getRuntimeConfig,
  setRuntimeConfig,
  getPrivateKey,
  setPrivateKey,
  readPrivateKeyFromPath,
  secureConfigToken,
}) => {
  // --- Scope definitions ---
  // read:  export config (without private key)
  // write: import config (mutates runtime state)
  // admin: export with private key (most privileged)
  const SCOPE_READ = 'read';
  const SCOPE_WRITE = 'write';
  const SCOPE_ADMIN = 'admin';

  // --- Brute-force protection: simple in-memory sliding window ---
  const RATE_LIMIT_WINDOW_MS = 60_000;
  const RATE_LIMIT_MAX_ATTEMPTS = 10;
  const failedAttempts = [];

  const isRateLimited = () => {
    const now = Date.now();
    // Purge expired entries
    while (failedAttempts.length > 0 && failedAttempts[0] < now - RATE_LIMIT_WINDOW_MS) {
      failedAttempts.shift();
    }
    return failedAttempts.length >= RATE_LIMIT_MAX_ATTEMPTS;
  };

  const recordFailedAttempt = () => {
    failedAttempts.push(Date.now());
  };

  // --- Auth: Bearer-only, no query/body token fallback ---
  const extractBearerToken = (req) => {
    const authHeader = String(req.get('authorization') || '');
    if (!authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.slice(7).trim();
  };

  const resolveRequiredScope = (method, path, secureFlag) => {
    if (path === '/signing-domain-config/export' && method === 'GET') {
      return secureFlag ? SCOPE_ADMIN : SCOPE_READ;
    }
    if (path === '/signing-domain-config/import' && method === 'POST') {
      return secureFlag ? SCOPE_ADMIN : SCOPE_WRITE;
    }
    return null;
  };

  const hasSecureAccess = (req) => {
    if (!secureConfigToken) {
      return false;
    }
    const bearer = extractBearerToken(req);
    return bearer === secureConfigToken;
  };

  const authenticate = (req, res, requiredScope) => {
    if (isRateLimited()) {
      console.warn('[AUDIT] auth_rate_limited', JSON.stringify({
        path: req.path,
        ip: req.ip,
        reason: 'too_many_failed_attempts',
      }));
      res.status(429).json({
        status: 'error',
        code: 'RATE_LIMITED',
        message: 'Too many failed authentication attempts. Retry later.',
      });
      return false;
    }

    if (!secureConfigToken) {
      console.error('[AUDIT] auth_misconfigured', JSON.stringify({
        path: req.path,
        reason: 'no_secure_config_token_configured',
      }));
      res.status(500).json({
        status: 'error',
        code: 'MISCONFIGURED',
        message: 'Secure config token is not configured on the server.',
      });
      return false;
    }

    const bearer = extractBearerToken(req);
    if (!bearer) {
      recordFailedAttempt();
      console.warn('[AUDIT] auth_denied', JSON.stringify({
        path: req.path,
        ip: req.ip,
        reason: 'missing_bearer_token',
        requiredScope,
      }));
      res.status(401).json({
        status: 'error',
        code: 'AUTH_REQUIRED',
        message: 'Authorization: Bearer <token> header is required.',
      });
      return false;
    }

    if (bearer !== secureConfigToken) {
      recordFailedAttempt();
      console.warn('[AUDIT] auth_denied', JSON.stringify({
        path: req.path,
        ip: req.ip,
        reason: 'invalid_token',
        requiredScope,
      }));
      res.status(403).json({
        status: 'error',
        code: 'FORBIDDEN',
        message: 'Invalid or revoked token.',
      });
      return false;
    }

    return true;
  };

  // --- Payload validation ---
  const validateImportPayload = (payload) => {
    if (!payload || typeof payload !== 'object') {
      return { ok: false, error: 'Payload must be a JSON object' };
    }

    if (payload.schemaVersion !== 'v1') {
      return { ok: false, error: 'Unsupported schemaVersion. Expected v1' };
    }

    const cfg = payload.config;
    if (!cfg || typeof cfg !== 'object') {
      return { ok: false, error: 'config object is required' };
    }

    if (typeof cfg.domainName !== 'string' || !cfg.domainName.trim()) {
      return { ok: false, error: 'config.domainName must be a non-empty string' };
    }

    if (typeof cfg.keySelector !== 'string' || !cfg.keySelector.trim()) {
      return { ok: false, error: 'config.keySelector must be a non-empty string' };
    }

    if (!Array.isArray(cfg.dkimDomains) || cfg.dkimDomains.length === 0 || cfg.dkimDomains.some((d) => typeof d !== 'string' || !d.trim())) {
      return { ok: false, error: 'config.dkimDomains must be a non-empty string array' };
    }

    return { ok: true };
  };

  const buildDiff = (before, after) => {
    const diff = {};
    const keys = ['domainName', 'keySelector', 'dkimDomains', 'privateKeyPath'];
    keys.forEach((key) => {
      const beforeValue = JSON.stringify(before[key]);
      const afterValue = JSON.stringify(after[key]);
      if (beforeValue !== afterValue) {
        diff[key] = { before: before[key], after: after[key] };
      }
    });
    return diff;
  };

  // --- Routes ---

  app.get('/signing-domain-config/export', (req, res) => {
    const secure = String(req.query.secure || '').toLowerCase() === 'true';
    const requiredScope = resolveRequiredScope('GET', '/signing-domain-config/export', secure);

    // Any export requires at least read scope; secure export requires admin scope
    if (secure) {
      if (!authenticate(req, res, requiredScope)) {
        return;
      }
    }

    const runtimeConfig = getRuntimeConfig();
    const allowPrivateKey = secure && hasSecureAccess(req);

    const bundle = {
      schemaVersion: 'v1',
      exportedAt: new Date().toISOString(),
      config: {
        domainName: runtimeConfig.domainName,
        keySelector: runtimeConfig.keySelector,
        dkimDomains: runtimeConfig.dkimDomains,
        privateKeyPath: runtimeConfig.privateKeyPath,
        privateKeyIncluded: allowPrivateKey,
      },
    };

    if (allowPrivateKey) {
      bundle.config.privateKey = getPrivateKey();
    }

    res.status(200).json(bundle);
  });

  app.post('/signing-domain-config/import', (req, res) => {
    const secure = req.body && req.body.secure === true;
    const requiredScope = resolveRequiredScope('POST', '/signing-domain-config/import', secure);

    // Import always requires authentication (write scope minimum)
    if (!authenticate(req, res, requiredScope)) {
      return;
    }

    const validation = validateImportPayload(req.body);
    if (!validation.ok) {
      return res.status(400).json({ status: 'error', message: validation.error });
    }

    const runtimeConfig = getRuntimeConfig();
    const dryRun = req.body.dryRun !== false;
    const allowPrivateKey = secure;

    const importedConfig = {
      schemaVersion: 'v1',
      domainName: req.body.config.domainName.trim().toLowerCase(),
      keySelector: req.body.config.keySelector.trim(),
      dkimDomains: req.body.config.dkimDomains.map((d) => d.trim().toLowerCase()).filter(Boolean),
      privateKeyPath: req.body.config.privateKeyPath || runtimeConfig.privateKeyPath,
    };

    const diff = buildDiff(runtimeConfig, importedConfig);

    if (dryRun) {
      return res.status(200).json({
        status: 'ok',
        applied: false,
        dryRun: true,
        schemaVersion: 'v1',
        diff,
      });
    }

    if (secure && req.body.config.privateKey && !allowPrivateKey) {
      return res.status(403).json({ status: 'error', message: 'Secure import requested but token is missing or invalid' });
    }

    setRuntimeConfig(importedConfig);

    if (secure && typeof req.body.config.privateKey === 'string' && req.body.config.privateKey.trim()) {
      setPrivateKey(req.body.config.privateKey);
    } else {
      setPrivateKey(readPrivateKeyFromPath(importedConfig.privateKeyPath));
    }

    console.log('[AUDIT] config_imported', JSON.stringify({
      domainName: importedConfig.domainName,
      keySelector: importedConfig.keySelector,
      dkimDomains: importedConfig.dkimDomains,
      secure,
      diff,
    }));

    return res.status(200).json({
      status: 'ok',
      applied: true,
      dryRun: false,
      schemaVersion: 'v1',
      diff,
    });
  });
};

module.exports = { registerSigningDomainConfigRoutes };
