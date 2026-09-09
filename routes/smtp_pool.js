/**
 * SMTP Connection Pool Module
 * Issue #39: SMTP connection pooling and reuse
 *
 * Maintains a pool of persistent SMTP connections per destination domain.
 * Reuses established TLS connections to improve throughput and reduce latency.
 */

const nodemailer = require('nodemailer');
const { EventEmitter } = require('events');

// Pool configuration from environment
const POOL_SIZE = parseInt(process.env.SMTP_POOL_SIZE, 10) || 5;
const POOL_TIMEOUT = parseInt(process.env.SMTP_POOL_TIMEOUT, 10) || 30000; // 30s
const IDLE_TIMEOUT = parseInt(process.env.SMTP_IDLE_TIMEOUT, 10) || 300000; // 5min
const HEALTH_CHECK_INTERVAL = parseInt(process.env.SMTP_HEALTH_CHECK_INTERVAL, 10) || 60000; // 1min

// Prometheus metrics
const metrics = {
    poolSize: 0,
    activeConnections: 0,
    idleConnections: 0,
    waitTime: 0,
    totalRequests: 0,
    reusedConnections: 0,
    failedConnections: 0,
};

/**
 * Represents a pooled SMTP connection
 */
class PooledConnection {
    constructor(transporter, domain) {
        this.transporter = transporter;
        this.domain = domain;
        this.createdAt = Date.now();
        this.lastUsedAt = Date.now();
        this.isIdle = true;
        this.isHealthy = true;
        this.useCount = 0;
    }

    markUsed() {
        this.lastUsedAt = Date.now();
        this.isIdle = false;
        this.useCount++;
    }

    markIdle() {
        this.isIdle = true;
    }

    isExpired() {
        return Date.now() - this.lastUsedAt > IDLE_TIMEOUT;
    }

    async verify() {
        try {
            this.isHealthy = await this.transporter.verify();
        } catch (e) {
            this.isHealthy = false;
        }
        return this.isHealthy;
    }

    async close() {
        try {
            this.transporter.close();
        } catch (e) {
            // Ignore close errors
        }
    }
}

/**
 * SMTP Connection Pool per domain
 */
class SmtpConnectionPool extends EventEmitter {
    constructor(domain, options = {}) {
        super();
        this.domain = domain;
        this.options = options;
        this.connections = [];
        this.waitQueue = [];
        this.maxSize = options.size || POOL_SIZE;
        this.timeout = options.timeout || POOL_TIMEOUT;
        this.healthCheckTimer = null;
        this.isShuttingDown = false;

        this.startHealthCheck();
    }

    get activeConnections() {
        return this.connections.filter(c => !c.isIdle).length;
    }

    get idleConnections() {
        return this.connections.filter(c => c.isIdle).length;
    }

    /**
     * Create a new SMTP connection
     */
    async createConnection() {
        const transporter = nodemailer.createTransport({
            host: this.options.host || process.env.SMTP_HOST,
            port: parseInt(this.options.port || process.env.SMTP_PORT, 10),
            secure: (this.options.secure || process.env.SMTP_SECURE) === 'true',
            auth: {
                user: this.options.user || process.env.SMTP_USER,
                pass: this.options.pass || process.env.SMTP_PASS,
            },
            tls: {
                rejectUnauthorized: false,
            },
            pool: false, // We manage pooling ourselves
            dkim: this.options.dkim,
        });

        const conn = new PooledConnection(transporter, this.domain);
        return conn;
    }

    /**
     * Get a connection from the queue
     */
    async getConnection() {
        if (this.isShuttingDown) {
            throw new Error('Pool is shutting down');
        }

        metrics.totalRequests++;

        // Find an idle connection
        const idleConn = this.connections.find(c => c.isIdle && c.isHealthy && !c.isExpired());
        if (idleConn) {
            idleConn.markUsed();
            metrics.reusedConnections++;
            metrics.activeConnections = this.activeConnections;
            return idleConn;
        }

        // Create new connection if pool not full
        if (this.connections.length < this.maxSize) {
            const conn = await this.createConnection();
            conn.markUsed();
            this.connections.push(conn);
            metrics.poolSize = this.connections.length;
            metrics.activeConnections = this.activeConnections;
            return conn;
        }

        // Wait for a connection to become available
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                const idx = this.waitQueue.findIndex(item => item.resolve === resolve);
                if (idx !== -1) {
                    this.waitQueue.splice(idx, 1);
                }
                reject(new Error('Connection pool timeout'));
            }, this.timeout);

            this.waitQueue.push({
                resolve: (conn) => {
                    clearTimeout(timeout);
                    resolve(conn);
                },
                reject: (err) => {
                    clearTimeout(timeout);
                    reject(err);
                },
            });
        });
    }

    /**
     * Release a connection back to the queue
     */
    releaseConnection(conn) {
        conn.markIdle();
        metrics.idleConnections = this.idleConnections;
        metrics.activeConnections = this.activeConnections;

        // Check if anyone is waiting
        if (this.waitQueue.length > 0) {
            const waiter = this.waitQueue.shift();
            conn.markUsed();
            waiter.resolve(conn);
        }
    }

    /**
     * Remove a connection from the queue
     */
    async removeConnection(conn) {
        const idx = this.connections.indexOf(conn);
        if (idx !== -1) {
            this.connections.splice(idx, 1);
            await conn.close();
            metrics.poolSize = this.connections.length;
        }
    }

    /**
     * Start periodic health check
     */
    startHealthCheck() {
        this.healthCheckTimer = setInterval(async () => {
            for (const conn of [...this.connections]) {
                if (conn.isExpired() || !await conn.verify()) {
                    await this.removeConnection(conn);
                }
            }
        }, HEALTH_CHECK_INTERVAL);
    }

    /**
     * Get pool metrics
     */
    getMetrics() {
        return {
            domain: this.domain,
            totalConnections: this.connections.length,
            activeConnections: this.activeConnections,
            idleConnections: this.idleConnections,
            waitQueueLength: this.waitQueue.length,
        };
    }

    /**
     * Shutdown the pool
     */
    async shutdown() {
        this.isShuttingDown = true;
        if (this.healthCheckTimer) {
            clearInterval(this.healthCheckTimer);
        }
        await Promise.all(this.connections.map(c => c.close()));
        this.connections = [];
        this.waitQueue = [];
    }
}

/**
 * Global pool manager
 */
class SmtpPoolManager {
    constructor() {
        this.pools = new Map();
    }

    /**
     * Get or create a pool for a domain
     */
    getPool(domain, options = {}) {
        if (!this.pools.has(domain)) {
            this.pools.set(domain, new SmtpConnectionPool(domain, options));
        }
        return this.pools.get(domain);
    }

    /**
     * Send mail using a pooled connection
     */
    async sendMail(domain, mailOptions, poolOptions = {}) {
        const pool = this.getPool(domain, poolOptions);
        const conn = await pool.getConnection();
        try {
            const result = await conn.transporter.sendMail(mailOptions);
            pool.releaseConnection(conn);
            return result;
        } catch (error) {
            metrics.failedConnections++;
            // Remove failed connection
            await pool.removeConnection(conn);
            throw error;
        }
    }

    /**
     * Get metrics for all pools
     */
    getAllMetrics() {
        const poolMetrics = {};
        for (const [domain, pool] of this.pools) {
            poolMetrics[domain] = pool.getMetrics();
        }
        return {
            ...metrics,
            pools: poolMetrics,
        };
    }

    /**
     * Shutdown all pools
     */
    async shutdownAll() {
        for (const pool of this.pools.values()) {
            await pool.shutdown();
        }
        this.pools.clear();
    }
}

// Singleton instance
const poolManager = new SmtpPoolManager();

module.exports = {
    SmtpPoolManager,
    SmtpConnectionPool,
    PooledConnection,
    poolManager,
    metrics,
    POOL_SIZE,
    POOL_TIMEOUT,
    IDLE_TIMEOUT,
    HEALTH_CHECK_INTERVAL,
};
