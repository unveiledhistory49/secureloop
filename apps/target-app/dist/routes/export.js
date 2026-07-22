"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const child_process_1 = require("child_process");
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1059.004 Command Injection endpoint
router.post('/', (req, res) => {
    const { filename, format } = req.body;
    if (!filename) {
        return res.status(400).json({ error: 'Filename is required' });
    }
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: Shell command string concatenation (T1059.004)
        const cmd = `echo "Exporting data to ${filename}" && echo "Format: ${format || 'txt'}"`;
        (0, child_process_1.exec)(cmd, (error, stdout, stderr) => {
            if (error) {
                (0, logger_1.writeSecurityLog)({
                    timestamp: new Date().toISOString(),
                    traceId: req.traceId || 'unknown',
                    requestId: `req-${Date.now()}`,
                    clientIp: req.ip || '127.0.0.1',
                    method: req.method,
                    url: req.originalUrl,
                    statusCode: 500,
                    userAgent: req.headers['user-agent'] || '',
                    bodyPayload: req.body,
                    headers: req.headers,
                    securityEvent: {
                        type: 'COMMAND_EXECUTION_ERROR',
                        details: `Command injection execution payload triggered command: ${cmd}`,
                        severity: 'HIGH'
                    }
                });
            }
            return res.json({
                message: 'Report exported successfully',
                commandExecuted: cmd,
                output: stdout,
                error: stderr || undefined,
                mode: 'VULNERABLE'
            });
        });
    }
    else {
        // HARDENED MODE: Strict input sanitization (alphanumeric only) & no shell chaining
        const safeFilename = String(filename).replace(/[^a-zA-Z0-9_-]/g, '');
        const safeFormat = String(format || 'txt').replace(/[^a-zA-Z0-9]/g, '');
        return res.json({
            message: 'Report exported securely',
            filename: `${safeFilename}.${safeFormat}`,
            mode: 'HARDENED'
        });
    }
});
exports.default = router;
