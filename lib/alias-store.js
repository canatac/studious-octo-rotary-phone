/**
 * Masked Email Alias Store
 * Issue #54: Masked email alias management API
 *
 * File-backed JSON store for alias persistence.
 * Supports create/deactivate/list/forward operations.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.ALIAS_DATA_DIR || path.join(__dirname, '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'aliases.json');

// In-memory cache
let aliases = new Map();
let loaded = false;

/**
 * Ensure data directory exists and load store from disk
 */
function ensureLoaded() {
  if (loaded) return;
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (fs.existsSync(STORE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
      aliases = new Map(Object.entries(data));
    }
  } catch (e) {
    console.error('[alias-store] Failed to load store:', e.message);
    aliases = new Map();
  }
  loaded = true;
}

/**
 * Persist store to disk
 */
function persist() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const obj = Object.fromEntries(aliases);
    fs.writeFileSync(STORE_FILE, JSON.stringify(obj, null, 2));
  } catch (e) {
    console.error('[alias-store] Failed to persist:', e.message);
  }
}

/**
 * Generate a random alias prefix (alphanumeric, 8 chars)
 */
function generateAliasPrefix() {
  return crypto.randomBytes(4).toString('hex'); // 8 hex chars
}

/**
 * Create a new masked alias
 */
function createAlias(userId, domain, label) {
  ensureLoaded();
  const prefix = generateAliasPrefix();
  const alias = `${prefix}@${domain}`;
  const id = crypto.randomUUID();
  const record = {
    id,
    alias,
    userId,
    domain,
    label: label || null,
    active: true,
    createdAt: new Date().toISOString(),
    forwardedCount: 0,
    lastForwardedAt: null,
  };
  aliases.set(id, record);
  persist();
  return record;
}

/**
 * Get alias by ID
 */
function getAlias(id) {
  ensureLoaded();
  return aliases.get(id) || null;
}

/**
 * List all aliases for a user
 */
function listAliases(userId) {
  ensureLoaded();
  const results = [];
  for (const [, record] of aliases) {
    if (record.userId === userId) {
      results.push(record);
    }
  }
  return results.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/**
 * Deactivate an alias (soft delete - stops forwarding)
 */
function deactivateAlias(id, userId) {
  ensureLoaded();
  const record = aliases.get(id);
  if (!record) return null;
  if (record.userId !== userId) return { error: 'forbidden' };
  record.active = false;
  record.deactivatedAt = new Date().toISOString();
  persist();
  return record;
}

/**
 * Delete an alias permanently
 */
function deleteAlias(id, userId) {
  ensureLoaded();
  const record = aliases.get(id);
  if (!record) return false;
  if (record.userId !== userId) return false;
  aliases.delete(id);
  persist();
  return true;
}

/**
 * Record a forwarding event
 */
function recordForward(id) {
  ensureLoaded();
  const record = aliases.get(id);
  if (!record) return;
  record.forwardedCount = (record.forwardedCount || 0) + 1;
  record.lastForwardedAt = new Date().toISOString();
  persist();
}

/**
 * Find alias by its email address (only active ones)
 */
function findByAlias(aliasEmail) {
  ensureLoaded();
  for (const [, record] of aliases) {
    if (record.alias === aliasEmail && record.active) {
      return record;
    }
  }
  return null;
}

/**
 * Get alias count for a user
 */
function getUserAliasCount(userId) {
  ensureLoaded();
  let count = 0;
  for (const [, record] of aliases) {
    if (record.userId === userId && record.active) {
      count++;
    }
  }
  return count;
}

module.exports = {
  createAlias,
  getAlias,
  listAliases,
  deactivateAlias,
  deleteAlias,
  recordForward,
  findByAlias,
  getUserAliasCount,
};
