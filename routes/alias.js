/**
 * Masked Email Alias Management API
 * Issue #54: Masked email alias management API
 *
 * Routes for creating, listing, deactivating, and deleting masked email aliases.
 * Also provides a forwarding hook for the SMTP inbound handler.
 */

const express = require('express');
const aliasStore = require('../lib/alias-store');

// Domain for aliases (from env or default)
const ALIAS_DOMAIN = process.env.ALIAS_DOMAIN || 'misfits.ai';

// Plan limits
const FREE_ALIAS_LIMIT = 10;
const PRO_ALIAS_LIMIT = Infinity; // unlimited

function registerAliasRoutes(app) {

  /**
   * POST /api/aliases
   * Create a new masked alias
   * Body: { userId, label? }
   */
  app.post('/api/aliases', (req, res) => {
    const { userId, label } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'bad_request', message: 'userId is required' });
    }

    // Check plan limits
    const currentCount = aliasStore.getUserAliasCount(userId);
    // For now, treat all users as Free plan (Pro plan check would come from user service)
    if (currentCount >= FREE_ALIAS_LIMIT) {
      return res.status(403).json({
        error: 'limit_reached',
        message: `Free plan limit reached (${FREE_ALIAS_LIMIT} aliases). Upgrade to Pro for unlimited aliases.`,
        limit: FREE_ALIAS_LIMIT,
        current: currentCount,
      });
    }

    const record = aliasStore.createAlias(userId, ALIAS_DOMAIN, label);
    return res.status(201).json(record);
  });

  /**
   * GET /api/aliases
   * List all aliases for a user
   * Query: ?userId=xxx
   */
  app.get('/api/aliases', (req, res) => {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ error: 'bad_request', message: 'userId query parameter is required' });
    }

    const aliases = aliasStore.listAliases(userId);
    return res.json({ aliases, count: aliases.length });
  });

  /**
   * GET /api/aliases/:id
   * Get a specific alias
   */
  app.get('/api/aliases/:id', (req, res) => {
    const { id } = req.params;
    const record = aliasStore.getAlias(id);

    if (!record) {
      return res.status(404).json({ error: 'not_found', message: 'Alias not found' });
    }

    return res.json(record);
  });

  /**
   * PATCH /api/aliases/:id/deactivate
   * Deactivate an alias (stops forwarding, soft delete)
   */
  app.patch('/api/aliases/:id/deactivate', (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'bad_request', message: 'userId is required' });
    }

    const result = aliasStore.deactivateAlias(id, userId);
    if (!result) {
      return res.status(404).json({ error: 'not_found', message: 'Alias not found' });
    }
    if (result.error === 'forbidden') {
      return res.status(403).json({ error: 'forbidden', message: 'Not your alias' });
    }

    return res.json(result);
  });

  /**
   * DELETE /api/aliases/:id
   * Permanently delete an alias
   */
  app.delete('/api/aliases/:id', (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'bad_request', message: 'userId is required' });
    }

    const deleted = aliasStore.deleteAlias(id, userId);
    if (!deleted) {
      return res.status(404).json({ error: 'not_found', message: 'Alias not found or forbidden' });
    }

    return res.status(204).send();
  });

  /**
   * GET /api/aliases/stats
   * Get alias statistics (counts, forwarding totals)
   */
  app.get('/api/aliases/stats', (req, res) => {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ error: 'bad_request', message: 'userId is required' });
    }

    const aliases = aliasStore.listAliases(userId);
    const active = aliases.filter(a => a.active);
    const totalForwarded = aliases.reduce((sum, a) => sum + (a.forwardedCount || 0), 0);

    return res.json({
      total: aliases.length,
      active: active.length,
      deactivated: aliases.length - active.length,
      totalForwarded,
      limit: FREE_ALIAS_LIMIT,
    });
  });
}

/**
 * Forwarding hook: check if a recipient is an alias and return the real user.
 * This is called by the inbound SMTP handler.
 * @param {string} toEmail - The recipient email address
 * @returns {object|null} - { aliasId, userId } or null if not an alias
 */
function resolveAliasRecipient(toEmail) {
  const record = aliasStore.findByAlias(toEmail.toLowerCase());
  if (!record) return null;
  return {
    aliasId: record.id,
    userId: record.userId,
    alias: record.alias,
  };
}

/**
 * Record that an alias email was forwarded
 * @param {string} aliasId
 */
function recordAliasForward(aliasId) {
  aliasStore.recordForward(aliasId);
}

module.exports = {
  registerAliasRoutes,
  resolveAliasRecipient,
  recordAliasForward,
};
