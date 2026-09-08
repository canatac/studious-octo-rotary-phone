const registerSigningDomainConfigRoutes = ({
  app,
  getRuntimeConfig,
  setRuntimeConfig,
  getPrivateKey,
  setPrivateKey,
  readPrivateKeyFromPath,
  secureConfigToken,
}) => {
  const hasSecureAccess = (req) => {
    if (!secureConfigToken) {
      return false;
    }
    const authHeader = String(req.get('authorization') || '');
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const bodyToken = req.body && typeof req.body.token === 'string' ? req.body.token.trim() : '';
    const queryToken = typeof req.query.token === 'string' ? req.query.token.trim() : '';
    return bearer === secureConfigToken || bodyToken === secureConfigToken || queryToken === secureConfigToken;
  };

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

  app.get('/signing-domain-config/export', (req, res) => {
    const runtimeConfig = getRuntimeConfig();
    const secure = String(req.query.secure || '').toLowerCase() === 'true';
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
    const validation = validateImportPayload(req.body);
    if (!validation.ok) {
      return res.status(400).json({ status: 'error', message: validation.error });
    }

    const runtimeConfig = getRuntimeConfig();
    const dryRun = req.body.dryRun !== false;
    const secure = req.body.secure === true;
    const allowPrivateKey = secure && hasSecureAccess(req);

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
