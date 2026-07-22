"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const database_1 = require("../db/database");
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1190 SQL Injection endpoint
router.get('/', (req, res) => {
    const query = req.query.q || '';
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: Raw SQL String Concatenation (T1190)
        const sql = `SELECT * FROM products WHERE category = '${query}' OR name LIKE '%${query}%'`;
        database_1.db.all(sql, (err, rows) => {
            if (err) {
                (0, logger_1.writeSecurityLog)({
                    timestamp: new Date().toISOString(),
                    traceId: req.traceId || 'unknown',
                    requestId: `req-${Date.now()}`,
                    clientIp: req.ip || '127.0.0.1',
                    method: req.method,
                    url: req.originalUrl,
                    statusCode: 500,
                    userAgent: req.headers['user-agent'] || '',
                    bodyPayload: {},
                    headers: req.headers,
                    securityEvent: {
                        type: 'SQL_ERROR_EXPLOIT',
                        details: `SQL error triggered by query: ${query}. Error: ${err.message}`,
                        severity: 'HIGH'
                    }
                });
                return res.status(500).json({ error: 'Database query execution error', details: err.message, query: sql });
            }
            return res.json({ mode: 'VULNERABLE', results: rows });
        });
    }
    else {
        // HARDENED MODE: Parameterized Query
        const sql = `SELECT * FROM products WHERE category = ? OR name LIKE ?`;
        const searchPattern = `%${query}%`;
        database_1.db.all(sql, [query, searchPattern], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            return res.json({ mode: 'HARDENED', results: rows });
        });
    }
});
exports.default = router;
