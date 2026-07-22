"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_1 = require("../db/database");
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1110 Brute Force & Login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    database_1.db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user || user.password !== password) {
            // Log failed login attempt for T1110 detection
            (0, logger_1.writeSecurityLog)({
                timestamp: new Date().toISOString(),
                traceId: req.traceId || 'unknown',
                requestId: `req-${Date.now()}`,
                clientIp: req.ip || '127.0.0.1',
                method: req.method,
                url: req.originalUrl,
                statusCode: 401,
                userAgent: req.headers['user-agent'] || '',
                bodyPayload: { username, password: '***' },
                headers: req.headers,
                securityEvent: {
                    type: 'AUTH_FAILURE',
                    details: `Failed authentication attempt for username: ${username}`,
                    severity: 'MEDIUM'
                }
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // Generate JWT
        const token = jsonwebtoken_1.default.sign({ id: user.id, username: user.username, role: user.role }, config_1.config.jwtSecret, { expiresIn: '2h' });
        return res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username, role: user.role }
        });
    });
});
// Endpoint to forge algorithmic vulnerability tokens in VULNERABLE mode (T1078)
router.post('/forge-token', (req, res) => {
    const { username, role, alg } = req.body;
    if (config_1.config.securityMode === 'VULNERABLE' && alg === 'none') {
        // Manually construct alg: none header
        const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ id: 'usr-999', username: username || 'hacker', role: role || 'ADMIN' })).toString('base64url');
        const forgedToken = `${header}.${payload}.`;
        return res.json({ token: forgedToken, note: 'VULNERABLE MODE: Forged alg=none JWT issued' });
    }
    // Standard token
    const token = jsonwebtoken_1.default.sign({ id: 'usr-002', username: username || 'alice', role: role || 'USER' }, config_1.config.jwtSecret);
    return res.json({ token });
});
exports.default = router;
