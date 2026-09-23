/**
 * DKIM2 Signature Module
 * Issue #63: DKIM2 signature support — next-gen email signing
 *
 * DKIM2 uses ed25519-sha512 algorithm for stronger security than DKIM1 (rsa-sha256).
 * Provides a /generate-dkim2 endpoint with automatic DKIM1 fallback.
 */

const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Supported DKIM algorithms
const DKIM_ALGORITHMS = {
    DKIM1: 'rsa-sha256',      // Legacy RSA-based
    DKIM2: 'ed25519-sha512',   // Next-gen Ed25519-based
};

/**
 * Resolve DKIM2 Ed25519 private key path
 * Environment: DKIM2_PRIVATE_KEY_PATH (falls back to PRIVATE_KEY_PATH with .ed25519 suffix)
 */
const resolveDkim2KeyPath = () => {
    if (process.env.DKIM2_PRIVATE_KEY_PATH) {
        return path.isAbsolute(process.env.DKIM2_PRIVATE_KEY_PATH)
            ? process.env.DKIM2_PRIVATE_KEY_PATH
            : path.join(process.env.DKIM2_PRIVATE_KEY_PATH);
    }
    // Derive from standard key path
    const basePath = process.env.PRIVATE_KEY_PATH || '';
    const parsed = path.parse(basePath);
    return path.join(parsed.dir, `${parsed.name}.ed25519${parsed.ext}`);
};

/**
 * Read DKIM2 private key
 */
const readDkim2PrivateKey = () => {
    const keyPath = resolveDkim2KeyPath();
    try {
        return fs.readFileSync(keyPath, 'utf8');
    } catch (err) {
        return null;
    }
};

/**
 * Generate an Ed25519 key pair for DKIM2 signing
 * Returns { privateKey (PEM), publicKey (base64), dnsRecord }
 */
const generateEd25519KeyPair = () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    // Extract raw public key bytes for DNS TXT record
    const publicKeyObj = crypto.createPublicKey(publicKey);
    const rawPublicKey = publicKeyObj.export({ type: 'spki', format: 'der' });
    // The last 32 bytes of SPKI DER for Ed25519 are the raw public key
    const rawKeyBytes = rawPublicKey.slice(rawPublicKey.length - 32);
    const base64PublicKey = rawKeyBytes.toString('base64');

    return {
        privateKey,
        publicKey: base64PublicKey,
        dnsRecord: `v=DKIM1; k=ed25519; p=${base64PublicKey}`,
    };
};

/**
 * Create a DKIM2-enabled transporter
 * Uses ed25519 keys when available, falls back to rsa-sha256
 */
const createDkim2Transporter = (signingDomain, keySelector, privateKey, options = {}) => {
    const dkimOptions = {
        domainName: signingDomain,
        keySelector: keySelector,
        privateKey: privateKey,
        // nodemailer-dkim supports algorithm field
        algorithm: options.algorithm || DKIM_ALGORITHMS.DKIM1,
    };

    return nodemailer.createTransport({
        host: options.host || process.env.SMTP_HOST,
        port: parseInt(options.port || process.env.SMTP_PORT, 10),
        secure: (options.secure || process.env.SMTP_SECURE) === 'true',
        auth: {
            user: options.user || process.env.SMTP_USER,
            pass: options.pass || process.env.SMTP_PASS,
        },
        tls: {
            rejectUnauthorized: false,
        },
        dkim: dkimOptions,
    });
};

/**
 * Sign email with DKIM2 (ed25519) or fallback to DKIM1 (rsa-sha256)
 * @param {Object} email - Email request { from, to, subject, text, html, attachments }
 * @param {Object} config - { signingDomain, keySelector, dkim1Key, dkim2Key, preferredAlgorithm }
 * @returns {Promise<Object>} Signing result with algorithm used
 */
const signEmailDkim2 = async (email, config = {}) => {
    const {
        signingDomain,
        keySelector,
        dkim1Key,
        dkim2Key,
        preferredAlgorithm = DKIM_ALGORITHMS.DKIM2,
    } = config;

    // Determine which algorithm to use
    let algorithm = DKIM_ALGORITHMS.DKIM1; // Default fallback
    let privateKey = dkim1Key;

    if (preferredAlgorithm === DKIM_ALGORITHMS.DKIM2 && dkim2Key) {
        algorithm = DKIM_ALGORITHMS.DKIM2;
        privateKey = dkim2Key;
    }

    return { algorithm, privateKey, signingDomain, keySelector };
};

/**
 * Register DKIM2 routes on the Express app
 */
const registerDkim2Routes = (app) => {
    if (!app) {
        throw new Error('app is required');
    }

    /**
     * POST /generate-dkim2
     * DKIM2 signature endpoint with ed25519 support and DKIM1 fallback
     */
    app.post('/generate-dkim2', async (req, res) => {
        const { from, to, subject, text, html, attachments, algorithm: requestedAlgorithm } = req.body;

        if (!from || !to || !subject || (!text && !html)) {
            res.status(400).json({
                status: 'error',
                message: 'Missing required fields: from, to, subject, and text or html',
            });
            return;
        }

        // Determine signing domain
        const configuredDomains = process.env.DKIM_DOMAINS
            ? process.env.DKIM_DOMAINS.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
            : [(process.env.DOMAIN_NAME || '').trim().toLowerCase()].filter(Boolean);

        const fromDomain = String(from).split('@').pop().trim().toLowerCase();
        const signingDomain = configuredDomains.includes(fromDomain)
            ? fromDomain
            : (configuredDomains[0] || process.env.DOMAIN_NAME || '');

        const keySelector = process.env.KEY_SELECTOR || 'default';
        const dkim2Key = readDkim2PrivateKey();
        const dkim1Key = (() => {
            try {
                const keyPath = process.env.PRIVATE_KEY_PATH;
                return keyPath ? fs.readFileSync(keyPath, 'utf8') : null;
            } catch {
                return null;
            }
        })();

        // Determine algorithm: requested > DKIM2 (if key available) > DKIM1 fallback
        let algorithm = DKIM_ALGORITHMS.DKIM1;
        let privateKey = dkim1Key;

        const preferredAlgo = requestedAlgorithm || DKIM_ALGORITHMS.DKIM2;
        if (preferredAlgo === DKIM_ALGORITHMS.DKIM2 && dkim2Key) {
            algorithm = DKIM_ALGORITHMS.DKIM2;
            privateKey = dkim2Key;
        } else if (preferredAlgo === DKIM_ALGORITHMS.DKIM2 && !dkim2Key) {
            // Fallback to DKIM1 when DKIM2 key not available
            algorithm = DKIM_ALGORITHMS.DKIM1;
            privateKey = dkim1Key;
        }

        if (!privateKey) {
            res.status(503).json({
                status: 'error',
                code: 'DKIM_KEY_UNAVAILABLE',
                message: 'No DKIM private key available for signing',
            });
            return;
        }

        // Create transporter with selected algorithm
        const transporter = createDkim2Transporter(signingDomain, keySelector, privateKey, { algorithm });

        // Derive plain text from HTML if needed
        const htmlToPlainText = (h) => String(h)
            .replace(/<style[\s\S]*?<\/style>/gi, ' ')
            .replace(/<script[\s\S]*?<\/script>/gi, ' ')
            .replace(/<\/?(p|div|br|li|tr|h[1-6])[^>]*>/gi, '\n')
            .replace(/<[^>]+>/g, '')
            .replace(/&nbsp;/gi, ' ')
            .replace(/&amp;/gi, '&')
            .replace(/&lt;/gi, '<')
            .replace(/&gt;/gi, '>')
            .replace(/&quot;/gi, '"')
            .replace(/&#39;/gi, "'")
            .replace(/[ \t]+\n/g, '\n')
            .replace(/\n{3,}/g, '\n\n')
            .trim();

        const plainText = (typeof text === 'string' && text.trim().length > 0)
            ? text
            : (html ? htmlToPlainText(html) : '');

        const normalizedAttachments = Array.isArray(attachments)
            ? attachments
                .filter((att) => att && typeof att.filename === 'string' && typeof att.dataBase64 === 'string' && att.dataBase64.trim().length > 0)
                .map((att) => ({
                    filename: String(att.filename).trim() || 'attachment.bin',
                    content: Buffer.from(att.dataBase64, 'base64'),
                    contentType: typeof att.contentType === 'string' && att.contentType.trim().length > 0
                        ? att.contentType.trim()
                        : undefined,
                }))
            : [];

        const mailOptions = {
            from,
            to,
            subject,
            text: plainText,
            html,
            attachments: normalizedAttachments,
        };

        try {
            const info = await transporter.sendMail(mailOptions);
            const accepted = Array.isArray(info.accepted) ? info.accepted : [];
            const acceptedByRemoteMx = accepted.length > 0;

            res.status(acceptedByRemoteMx ? 200 : 502).json({
                message: acceptedByRemoteMx
                    ? 'Email accepted by upstream SMTP server'
                    : 'Email was not accepted by upstream SMTP server',
                messageId: info.messageId,
                status: acceptedByRemoteMx ? 'success' : 'error',
                algorithm,
                algorithmFallback: (preferredAlgo === DKIM_ALGORITHMS.DKIM2 && algorithm === DKIM_ALGORITHMS.DKIM1),
                signingDomain,
                keySelector,
                acceptedByRemoteMx,
                accepted,
                rejected: Array.isArray(info.rejected) ? info.rejected : [],
                response: info.response || null,
            });
        } catch (error) {
            // If DKIM2 fails, attempt DKIM1 fallback
            if (algorithm === DKIM_ALGORITHMS.DKIM2 && dkim1Key) {
                try {
                    const fallbackTransporter = createDkim2Transporter(signingDomain, keySelector, dkim1Key, { algorithm: DKIM_ALGORITHMS.DKIM1 });
                    const info = await fallbackTransporter.sendMail(mailOptions);
                    const accepted = Array.isArray(info.accepted) ? info.accepted : [];
                    const acceptedByRemoteMx = accepted.length > 0;

                    res.status(acceptedByRemoteMx ? 200 : 502).json({
                        message: acceptedByRemoteMx
                            ? 'Email accepted by upstream SMTP server (DKIM1 fallback)'
                            : 'Email was not accepted by upstream SMTP server',
                        messageId: info.messageId,
                        status: acceptedByRemoteMx ? 'success' : 'error',
                        algorithm: DKIM_ALGORITHMS.DKIM1,
                        algorithmFallback: true,
                        fallbackReason: 'DKIM2 signing failed, fell back to DKIM1',
                        signingDomain,
                        keySelector,
                        acceptedByRemoteMx,
                        accepted,
                        rejected: Array.isArray(info.rejected) ? info.rejected : [],
                        response: info.response || null,
                    });
                    return;
                } catch (fallbackError) {
                    res.status(500).json({
                        status: 'error',
                        error: 'Failed to send email with both DKIM2 and DKIM1',
                        dkim2Error: error.message,
                        dkim1Error: fallbackError.message,
                    });
                    return;
                }
            }

            res.status(500).json({
                status: 'error',
                error: 'Failed to send email',
                message: error.message || 'Unknown SMTP error',
                algorithm,
            });
        }
    });

    /**
     * GET /dkim2/key-info
     * Returns DKIM2 key status and DNS record for publishing
     */
    app.get('/dkim2/key-info', (req, res) => {
        const dkim2Key = readDkim2PrivateKey();
        const keyPath = resolveDkim2KeyPath();
        const keyExists = dkim2Key !== null;

        let publicKeyBase64 = null;
        let dnsRecord = null;

        if (dkim2Key) {
            try {
                // Extract public key from private key PEM
                const privateKeyObj = crypto.createPrivateKey(dkim2Key);
                const pubDer = privateKeyObj.export({ type: 'pkcs8', format: 'der' });
                // For Ed25519 PKCS8 DER, public key is at a known offset
                // Alternative: derive from key pair generation
                const publicKeyObj = crypto.createPublicKey(privateKeyObj);
                const spkiDer = publicKeyObj.export({ type: 'spki', format: 'der' });
                const rawKeyBytes = spkiDer.slice(spkiDer.length - 32);
                publicKeyBase64 = rawKeyBytes.toString('base64');
                const selector = process.env.KEY_SELECTOR || 'default';
                const domain = req.query.domain || process.env.DOMAIN_NAME || '';
                dnsRecord = `v=DKIM1; k=ed25519; p=${publicKeyBase64}`;
            } catch (err) {
                // Key exists but couldn't parse
            }
        }

        res.status(200).json({
            status: keyExists ? 'available' : 'unavailable',
            algorithm: DKIM_ALGORITHMS.DKIM2,
            keyPath: keyPath || null,
            keyExists,
            publicKeyBase64,
            dnsRecord,
            selector: process.env.KEY_SELECTOR || 'default',
            domain: process.env.DOMAIN_NAME || null,
        });
    });

    /**
     * POST /dkim2/generate-key
     * Generate a new Ed25519 key pair for DKIM2 signing
     */
    app.post('/dkim2/generate-key', (req, res) => {
        try {
            const keyPair = generateEd25519KeyPair();
            const keyPath = resolveDkim2KeyPath();

            // Save private key if path is writable
            let saved = false;
            if (keyPath && process.env.DKIM2_KEY_GENERATION !== 'readonly') {
                try {
                    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
                    fs.writeFileSync(keyPath, keyPair.privateKey, { mode: 0o600 });
                    saved = true;
                } catch (writeErr) {
                    // Read-only mode — return key without saving
                }
            }

            res.status(200).json({
                status: 'generated',
                algorithm: DKIM_ALGORITHMS.DKIM2,
                publicKeyBase64: keyPair.publicKey,
                dnsRecord: keyPair.dnsRecord,
                keyPath: keyPath || null,
                saved,
                selector: process.env.KEY_SELECTOR || 'default',
                domain: process.env.DOMAIN_NAME || null,
                message: saved
                    ? 'Ed25519 key pair generated and saved'
                    : 'Ed25519 key pair generated (not saved — set DKIM2_PRIVATE_KEY_PATH and ensure writable)',
            });
        } catch (error) {
            res.status(500).json({
                status: 'error',
                message: `Failed to generate Ed25519 key pair: ${error.message}`,
            });
        }
    });

    /**
     * GET /dkim2/status
     * DKIM2 service status and capabilities
     */
    app.get('/dkim2/status', (req, res) => {
        const dkim2Key = readDkim2PrivateKey();
        const dkim1Key = (() => {
            try {
                const keyPath = process.env.PRIVATE_KEY_PATH;
                return keyPath ? fs.readFileSync(keyPath, 'utf8') : null;
            } catch {
                return null;
            }
        })();

        res.status(200).json({
            status: 'ok',
            algorithms: {
                DKIM1: {
                    algorithm: DKIM_ALGORITHMS.DKIM1,
                    available: dkim1Key !== null,
                    legacy: true,
                },
                DKIM2: {
                    algorithm: DKIM_ALGORITHMS.DKIM2,
                    available: dkim2Key !== null,
                    legacy: false,
                },
            },
            preferredAlgorithm: dkim2Key ? DKIM_ALGORITHMS.DKIM2 : DKIM_ALGORITHMS.DKIM1,
            fallbackEnabled: dkim1Key !== null,
            endpoints: [
                'POST /generate-dkim2 — Sign with DKIM2 (ed25519) + DKIM1 fallback',
                'GET /dkim2/key-info — DKIM2 key status and DNS record',
                'POST /dkim2/generate-key — Generate new Ed25519 key pair',
                'GET /dkim2/status — DKIM2 service status',
            ],
        });
    });
};

module.exports = {
    registerDkim2Routes,
    signEmailDkim2,
    createDkim2Transporter,
    generateEd25519KeyPair,
    readDkim2PrivateKey,
    resolveDkim2KeyPath,
    DKIM_ALGORITHMS,
};
