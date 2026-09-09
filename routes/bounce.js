/**
 * Bounce classification and handling (issue #46).
 *
 * Classifies bounces as hard/soft/complaint, auto-unsubscribes hard bounces,
 * and alerts on bounce spikes.
 */

const BOUNCE_PATTERNS = {
  hard: [
    /5\.1\.[012]/,
    /5\.1\.6/,
    /5\.1\.10/,
    /5\.2\.[012]/,
    /5\.4\.[01246]/,
    /5\.7\.[0123456]/,
    /user unknown/i,
    /recipient address rejected/i,
    /no such user/i,
    /mailbox not found/i,
    /account disabled/i,
    /account suspended/i,
    /account expired/i,
    /address rejected/i,
    /invalid recipient/i,
    /does not exist/i,
  ],
  soft: [
    /4\.[01234567]\./,
    /mailbox full/i,
    /quota exceeded/i,
    /insufficient space/i,
    /message size exceeds/i,
    /temporary failure/i,
    /try again/i,
    /defer/i,
    /greylist/i,
    /rate limit/i,
  ],
  complaint: [
    /abuse/i,
    /spam/i,
    /junk mail/i,
    /complaint/i,
    /fbl/i,
    /feedback loop/i,
    /unsubscribe/i,
    /opt-out/i,
  ],
};

const BOUNCE_CATEGORIES = {
  HARD: 'hard',
  SOFT: 'soft',
  COMPLAINT: 'complaint',
  UNKNOWN: 'unknown',
};

/**
 * Classify a bounce message.
 * @param {string} bounceMessage - The bounce message body or subject.
 * @returns {Object} Classification result with category, type, and reason.
 */
function classifyBounce(bounceMessage) {
  const message = String(bounceMessage || '');

  if (!message.trim()) {
    return {
      category: BOUNCE_CATEGORIES.UNKNOWN,
      type: 'empty',
      reason: 'Empty bounce message',
    };
  }

  for (const pattern of BOUNCE_PATTERNS.hard) {
    if (pattern.test(message)) {
      return {
        category: BOUNCE_CATEGORIES.HARD,
        type: 'hard',
        reason: `Matched hard bounce pattern: ${pattern.source}`,
      };
    }
  }

  for (const pattern of BOUNCE_PATTERNS.complaint) {
    if (pattern.test(message)) {
      return {
        category: BOUNCE_CATEGORIES.COMPLAINT,
        type: 'complaint',
        reason: `Matched complaint pattern: ${pattern.source}`,
      };
    }
  }

  for (const pattern of BOUNCE_PATTERNS.soft) {
    if (pattern.test(message)) {
      return {
        category: BOUNCE_CATEGORIES.SOFT,
        type: 'soft',
        reason: `Matched soft bounce pattern: ${pattern.source}`,
      };
    }
  }

  return {
    category: BOUNCE_CATEGORIES.UNKNOWN,
    type: 'unknown',
    reason: 'No matching bounce pattern found',
  };
}

/**
 * Parse DSN (Delivery Status Notification) from bounce.
 * @param {string} bounceMessage
 * @returns {Object} Parsed DSN fields.
 */
function parseDSN(bounceMessage) {
  const message = String(bounceMessage || '');
  const result = {
    action: null,
    status: null,
    diagnosticCode: null,
    remoteMta: null,
    reportingMta: null,
  };

  const actionMatch = message.match(/Action:\s*(failed|delayed|delivered|relayed|expanded)/i);
  if (actionMatch) {
    result.action = actionMatch[1].toLowerCase();
  }

  const statusMatch = message.match(/Status:\s*(\d\.\d+\.\d+)/i);
  if (statusMatch) {
    result.status = statusMatch[1];
  }

  const diagMatch = message.match(/Diagnostic-Code:\s*(.+)/i);
  if (diagMatch) {
    result.diagnosticCode = diagMatch[1].trim();
  }

  const remoteMtaMatch = message.match(/Remote-MTA:\s*(.+)/i);
  if (remoteMtaMatch) {
    result.remoteMta = remoteMtaMatch[1].trim();
  }

  const reportingMtaMatch = message.match(/Reporting-MTA:\s*(.+)/i);
  if (reportingMtaMatch) {
    result.reportingMta = reportingMtaMatch[1].trim();
  }

  return result;
}

/**
 * Bounce tracker state (in-memory, for spike detection).
 */
const bounceTracker = {
  counts: new Map(),
  windowMs: parseInt(process.env.BOUNCE_WINDOW_MS || '3600000', 10),
  get spikeThreshold() {
    return parseInt(process.env.BOUNCE_SPIKE_THRESHOLD || '10', 10);
  },
  alerts: [],
};

/**
 * Record a bounce and check for spikes.
 * @param {string} email - The recipient email that bounced.
 * @param {string} category - hard/soft/complaint/unknown.
 * @returns {Object} Result with spike alert if triggered.
 */
function recordBounce(email, category) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedEmail) {
    return { recorded: false, alert: null };
  }

  if (!bounceTracker.counts.has(normalizedEmail)) {
    bounceTracker.counts.set(normalizedEmail, {
      hard: 0,
      soft: 0,
      complaint: 0,
      total: 0,
      lastBounce: null,
      firstBounce: null,
    });
  }

  const record = bounceTracker.counts.get(normalizedEmail);
  record.total += 1;
  record[category] = (record[category] || 0) + 1;
  record.lastBounce = new Date().toISOString();
  if (!record.firstBounce) {
    record.firstBounce = record.lastBounce;
  }

  // Spike detection: total bounces in window exceeds threshold
  let alert = null;
  if (record.total >= bounceTracker.spikeThreshold) {
    alert = {
      type: 'bounce_spike',
      email: normalizedEmail,
      totalBounces: record.total,
      threshold: bounceTracker.spikeThreshold,
      windowMs: bounceTracker.windowMs,
      detectedAt: new Date().toISOString(),
    };
    bounceTracker.alerts.push(alert);
  }

  return { recorded: true, alert, record };
}

/**
 * Get bounce stats for an email.
 * @param {string} email
 * @returns {Object|null}
 */
function getBounceStats(email) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  return bounceTracker.counts.get(normalizedEmail) || null;
}

/**
 * Get all alerts.
 * @returns {Array}
 */
function getAlerts() {
  return [...bounceTracker.alerts];
}

/**
 * Clear alerts.
 */
function clearAlerts() {
  bounceTracker.alerts = [];
}

/**
 * Register bounce routes.
 * @param {Object} app - Express app.
 */
function registerBounceRoutes(app) {
  /**
   * POST /bounces/classify
   * Body: { "message": "..." }
   * Returns classification result.
   */
  app.post('/bounces/classify', (req, res) => {
    const { message } = req.body;
    const classification = classifyBounce(message);
    const dsn = parseDSN(message);

    res.status(200).json({
      status: 'classified',
      classification,
      dsn,
      processedAt: new Date().toISOString(),
    });
  });

  /**
   * POST /bounces/report
   * Body: { "email": "...", "message": "..." }
   * Records bounce, classifies, and checks for spikes.
   * Auto-unsubscribes hard bounces.
   */
  app.post('/bounces/report', (req, res) => {
    const { email, message } = req.body;

    if (!email) {
      res.status(400).json({
        status: 'error',
        message: 'email is required',
      });
      return;
    }

    const classification = classifyBounce(message);
    const dsn = parseDSN(message);
    const { alert, record } = recordBounce(email, classification.category);

    const result = {
      status: 'recorded',
      email,
      classification,
      dsn,
      record,
      alert,
      processedAt: new Date().toISOString(),
    };

    // Auto-unsubscribe hard bounces
    if (classification.category === BOUNCE_CATEGORIES.HARD) {
      result.autoUnsubscribed = true;
      result.autoUnsubscribeReason = 'Hard bounce detected - automatic unsubscription';
    } else {
      result.autoUnsubscribed = false;
    }

    res.status(200).json(result);
  });

  /**
   * GET /bounces/stats/:email
   * Returns bounce stats for an email.
   */
  app.get('/bounces/stats/:email', (req, res) => {
    const stats = getBounceStats(req.params.email);
    if (!stats) {
      res.status(404).json({
        status: 'not_found',
        email: req.params.email,
        message: 'No bounce records found for this email',
      });
      return;
    }

    res.status(200).json({
      status: 'found',
      email: req.params.email,
      stats,
    });
  });

  /**
   * GET /bounces/alerts
   * Returns all bounce spike alerts.
   */
  app.get('/bounces/alerts', (req, res) => {
    res.status(200).json({
      status: 'ok',
      alerts: getAlerts(),
      count: getAlerts().length,
    });
  });

  /**
   * POST /bounces/alerts/clear
   * Clears all alerts.
   */
  app.post('/bounces/alerts/clear', (req, res) => {
    clearAlerts();
    res.status(200).json({
      status: 'ok',
      message: 'Alerts cleared',
    });
  });
}

module.exports = {
  registerBounceRoutes,
  classifyBounce,
  parseDSN,
  recordBounce,
  getBounceStats,
  getAlerts,
  clearAlerts,
  BOUNCE_CATEGORIES,
  BOUNCE_PATTERNS,
};
