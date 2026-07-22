"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
const uploadDir = path_1.default.resolve(__dirname, '../../uploads');
if (!fs_1.default.existsSync(uploadDir)) {
    fs_1.default.mkdirSync(uploadDir, { recursive: true });
}
// Seed a sample file
fs_1.default.writeFileSync(path_1.default.join(uploadDir, 'sample.txt'), 'SecureLoop Upload Directory Sample File\n');
// Path Traversal / Arbitrary File Read endpoint
router.get('/preview', (req, res) => {
    const fileParam = req.query.file;
    if (!fileParam) {
        return res.status(400).json({ error: 'File parameter required' });
    }
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: Path Traversal (Arbitrary File Read)
        const targetPath = path_1.default.resolve(uploadDir, fileParam);
        if (fileParam.includes('..') || fileParam.includes('/etc/')) {
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
                    type: 'PATH_TRAVERSAL_ATTEMPT',
                    details: `Path traversal payload requested: ${fileParam}`,
                    severity: 'HIGH'
                }
            });
        }
        try {
            if (fs_1.default.existsSync(targetPath)) {
                const content = fs_1.default.readFileSync(targetPath, 'utf-8');
                return res.json({ filename: fileParam, contentSnippet: content.substring(0, 1000), mode: 'VULNERABLE' });
            }
            else {
                return res.status(404).json({ error: 'File not found', pathAttempted: targetPath });
            }
        }
        catch (err) {
            return res.status(500).json({ error: 'Error reading file', details: err.message });
        }
    }
    else {
        // HARDENED MODE: Sanitize file path using path.basename
        const safeFilename = path_1.default.basename(fileParam);
        const safePath = path_1.default.join(uploadDir, safeFilename);
        try {
            if (fs_1.default.existsSync(safePath)) {
                const content = fs_1.default.readFileSync(safePath, 'utf-8');
                return res.json({ filename: safeFilename, contentSnippet: content.substring(0, 1000), mode: 'HARDENED' });
            }
            else {
                return res.status(404).json({ error: 'File not found in upload sandbox' });
            }
        }
        catch (err) {
            return res.status(500).json({ error: 'Error reading file' });
        }
    }
});
exports.default = router;
