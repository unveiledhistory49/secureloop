"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const url_1 = require("url");
const config_1 = require("../config");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1041 / SSRF External URL fetcher
router.get('/', (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL query parameter required' });
    }
    let parsedUrl;
    try {
        parsedUrl = new url_1.URL(targetUrl);
    }
    catch (e) {
        return res.status(400).json({ error: 'Invalid URL format' });
    }
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: Arbitrary outbound HTTP fetch (SSRF to local/cloud metadata)
        const client = parsedUrl.protocol === 'https:' ? https_1.default : http_1.default;
        const request = client.get(targetUrl, (response) => {
            let data = '';
            response.on('data', (chunk) => { data += chunk; });
            response.on('end', () => {
                if (res.headersSent)
                    return;
                // Detect metadata or internal loopback targets for logging
                if (targetUrl.includes('169.254.169.254') || targetUrl.includes('127.0.0.1') || targetUrl.includes('localhost')) {
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
                            type: 'SSRF_METADATA_ATTEMPT',
                            details: `SSRF target fetch triggered for sensitive IP: ${targetUrl}`,
                            severity: 'HIGH'
                        }
                    });
                }
                return res.json({
                    status: response.statusCode,
                    headers: response.headers,
                    dataSnippet: data.substring(0, 500),
                    mode: 'VULNERABLE'
                });
            });
        });
        request.on('error', (err) => {
            if (res.headersSent)
                return;
            return res.status(500).json({ error: 'Failed to fetch target URL', details: err.message, mode: 'VULNERABLE' });
        });
        request.setTimeout(3000, () => {
            request.destroy();
            if (!res.headersSent) {
                return res.status(504).json({ error: 'Request timeout fetching URL' });
            }
        });
    }
    else {
        // HARDENED MODE: Block private IPs, RFC1918, localhost & cloud metadata
        const hostname = parsedUrl.hostname.toLowerCase();
        const isPrivate = hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname === '169.254.169.254' ||
            hostname.startsWith('10.') ||
            hostname.startsWith('192.168.') ||
            hostname.startsWith('172.16.') ||
            hostname.endsWith('.internal');
        if (isPrivate) {
            return res.status(403).json({
                error: 'Forbidden: Outbound requests to private subnets and cloud metadata endpoints are blocked.',
                hostname,
                mode: 'HARDENED'
            });
        }
        return res.json({
            message: `Fetching remote URL ${hostname} allowed in HARDENED mode`,
            hostname,
            mode: 'HARDENED'
        });
    }
});
exports.default = router;
