const registerDomainDeactivationRoute = ({
  app,
  parseConfiguredDomains,
  normalizeDomain,
  buildDeactivationImpact,
  deactivatedDomains,
  DEACTIVATION_CONFIRMATION_TOKEN,
}) => {
  app.post('/domains/:domain/deactivate', (req, res) => {
    const configuredDomains = parseConfiguredDomains();
    const domain = normalizeDomain(req.params.domain);
    const dryRunRequested = req.query.dryRun === 'true' || req.body?.dryRun === true;

    if (!domain || !configuredDomains.includes(domain)) {
      res.status(404).json({
        status: 'error',
        code: 'DOMAIN_NOT_CONFIGURED',
        message: 'Domain is not configured for DKIM signing',
        configuredDomains,
      });
      return;
    }

    const impact = buildDeactivationImpact(domain, configuredDomains);

    if (dryRunRequested) {
      res.status(200).json({
        status: 'dry_run',
        domain,
        impact,
        remediationSteps: [
          'Migrate aliases/signing traffic to another active domain',
          `Repeat request with confirmation='${DEACTIVATION_CONFIRMATION_TOKEN}' to confirm deactivation`,
        ],
      });
      return;
    }

    const confirmation = String(req.body?.confirmation || '').trim();
    if (confirmation !== DEACTIVATION_CONFIRMATION_TOKEN) {
      res.status(409).json({
        status: 'error',
        code: 'DEACTIVATION_CONFIRMATION_REQUIRED',
        message: 'Domain deactivation blocked. Explicit confirmation token required.',
        requiredConfirmation: DEACTIVATION_CONFIRMATION_TOKEN,
        impact,
        remediationSteps: [
          'Run dry-run first: POST /domains/{domain}/deactivate?dryRun=true',
          `Resubmit with confirmation='${DEACTIVATION_CONFIRMATION_TOKEN}'`,
        ],
      });
      return;
    }

    if (impact.remainingActiveDomains.length === 0) {
      res.status(409).json({
        status: 'error',
        code: 'LAST_SIGNING_DOMAIN_PROTECTED',
        message: 'Cannot deactivate the last active signing domain.',
        impact,
        remediationSteps: ['Add another active signing domain before deactivation.'],
      });
      return;
    }

    deactivatedDomains.add(domain);
    console.log('[AUDIT] domain_deactivated', JSON.stringify({
      domain,
      impactedEntitiesCount: 1 + impact.impactedRoutes.length + impact.impactedSelectors.length,
      remainingActiveDomains: impact.remainingActiveDomains,
    }));

    res.status(200).json({
      status: 'success',
      message: 'Domain deactivated with safeguard confirmation.',
      domain,
      impact,
    });
  });
};

module.exports = { registerDomainDeactivationRoute };
