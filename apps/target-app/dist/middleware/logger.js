"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.telemetryLogger = void 0;
exports.writeSecurityLog = writeSecurityLog;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const uuid_1 = require("uuid");
const config_1 = require("../config");
// Ensure log directory exists
const logDir = path_1.default.dirname(config_1.config.logFilePath);
if (!fs_1.default.existsSync(logDir)) {
    fs_1.default.mkdirSync(logDir, { recursive: true });
}
function writeSecurityLog(entry) {
    const line = JSON.stringify(entry) + '\n';
    fs_1.default.appendFileSync(config_1.config.logFilePath, line, 'utf-8');
}
const telemetryLogger = (req, res, next) => {
    const startTime = Date.now();
    const traceId = req.headers['x-trace-id'] || `trace-${(0, uuid_1.v4)()}`;
    const requestId = req.headers['x-request-id'] || `req-${(0, uuid_1.v4)()}`;
    req.traceId = traceId;
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const clientIp = Array.isArray(rawIp) ? rawIp[0] : rawIp.split(',')[0].trim();
    // Check IP blocklist (SOAR response enforcement)
    if (config_1.config.blockedIps.has(clientIp)) {
        writeSecurityLog({
            timestamp: new Date().toISOString(),
            traceId,
            requestId,
            clientIp,
            method: req.method,
            url: req.originalUrl,
            statusCode: 403,
            userAgent: req.headers['user-agent'] || '',
            bodyPayload: req.body,
            headers: { ...req.headers },
            securityEvent: {
                type: 'BLOCKED_IP_ATTEMPT',
                details: `Rejected connection from blocked IP: ${clientIp}`,
                severity: 'HIGH'
            }
        });
        return res.status(403).json({ error: 'Access denied: Your IP has been flagged and suspended by SecureLoop SOAR' });
    }
    // Intercept end to log response status
    res.on('finish', () => {
        const durationMs = Date.now() - startTime;
        const logEntry = {
            timestamp: new Date().toISOString(),
            traceId,
            requestId,
            clientIp,
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            durationMs,
            userAgent: req.headers['user-agent'] || 'unknown',
            bodyPayload: req.body || {},
            headers: {
                'host': req.headers.host || '',
                'content-type': req.headers['content-type'] || '',
                'user-agent': req.headers['user-agent'] || ''
            },
            userContext: req.user ? {
                userId: req.user.id,
                username: req.user.username,
                role: req.user.role
            } : undefined
        };
        writeSecurityLog(logEntry);
    });
    next();
};
exports.telemetryLogger = telemetryLogger;
