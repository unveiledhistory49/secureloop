"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1552 Unsecured Credentials
router.get('/config', (req, res) => {
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: Exposing sensitive configuration secrets in API response (T1552)
        (0, logger_1.writeSecurityLog)({
            timestamp: new Date().toISOString(),
            traceId: req.traceId || 'unknown',
            requestId: `req-${Date.now()}`,
            clientIp: req.ip || '127.0.0.1',
            method: req.method,
            url: req.originalUrl,
            statusCode: 200,
            userAgent: req.headers['user-agent'] || '',
            bodyPayload: {},
            headers: req.headers,
            securityEvent: {
                type: 'SECRET_LEAKAGE_EXPLOIT',
                details: 'VULNERABLE MODE: Debug endpoint exposed internal JWT secrets and database connection strings',
                severity: 'HIGH'
            }
        });
        return res.json({
            environment: 'development',
            jwtSecret: config_1.config.jwtSecret,
            databaseUrl: 'sqlite://root:SuperSecretDbPass2026@/root/secureloop/apps/target-app/secureloop.db',
            awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
            awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            mode: 'VULNERABLE'
        });
    }
    else {
        // HARDENED MODE: Redacted output
        return res.json({
            environment: 'production',
            jwtSecret: '[REDACTED]',
            databaseUrl: '[REDACTED]',
            awsAccessKey: '[REDACTED]',
            awsSecretKey: '[REDACTED]',
            mode: 'HARDENED'
        });
    }
});
exports.default = router;
