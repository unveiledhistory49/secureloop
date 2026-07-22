"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = require("../config");
const logger_1 = require("./logger");
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Authentication required: missing token' });
    }
    // Check if token is revoked in SOAR engine
    if (config_1.config.revokedTokens.has(token)) {
        return res.status(401).json({ error: 'Token has been revoked by security response' });
    }
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABLE MODE: Flawed JWT Verification
        try {
            // Decode header to check alg
            const decodedHeader = jsonwebtoken_1.default.decode(token, { complete: true });
            if (decodedHeader && decodedHeader.header && decodedHeader.header.alg === 'none') {
                // VULNERABILITY: Accepting unsigned 'none' algorithm JWT (T1078)
                const payload = jsonwebtoken_1.default.decode(token);
                req.user = payload;
                (0, logger_1.writeSecurityLog)({
                    timestamp: new Date().toISOString(),
                    traceId: req.traceId || 'unknown',
                    requestId: `req-${Date.now()}`,
                    clientIp: req.ip || '127.0.0.1',
                    method: req.method,
                    url: req.originalUrl,
                    userAgent: req.headers['user-agent'] || '',
                    bodyPayload: req.body,
                    headers: req.headers,
                    securityEvent: {
                        type: 'JWT_ALG_NONE_EXPLOIT',
                        details: `VULNERABLE MODE: Accepted JWT with alg=none for user ${payload?.username}`,
                        severity: 'HIGH'
                    }
                });
                return next();
            }
            // Default decode without strict signature check in vulnerable mode
            const decoded = jsonwebtoken_1.default.verify(token, config_1.config.jwtSecret);
            req.user = decoded;
            return next();
        }
        catch (err) {
            // In vulnerable mode, fall back to unsafe decode if secret mismatch
            const unsafeDecoded = jsonwebtoken_1.default.decode(token);
            if (unsafeDecoded) {
                req.user = unsafeDecoded;
                return next();
            }
            return res.status(403).json({ error: 'Invalid token' });
        }
    }
    else {
        // HARDENED MODE: Strict verification
        try {
            const decoded = jsonwebtoken_1.default.verify(token, config_1.config.jwtSecret, { algorithms: ['HS256'] });
            req.user = decoded;
            return next();
        }
        catch (err) {
            return res.status(403).json({ error: 'Invalid token or algorithm mismatch' });
        }
    }
};
exports.authenticateToken = authenticateToken;
