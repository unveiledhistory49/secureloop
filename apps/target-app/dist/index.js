"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const config_1 = require("./config");
const database_1 = require("./db/database");
const logger_1 = require("./middleware/logger");
const auth_1 = __importDefault(require("./routes/auth"));
const search_1 = __importDefault(require("./routes/search"));
const users_1 = __importDefault(require("./routes/users"));
const export_1 = __importDefault(require("./routes/export"));
const fetch_1 = __importDefault(require("./routes/fetch"));
const upload_1 = __importDefault(require("./routes/upload"));
const secrets_1 = __importDefault(require("./routes/secrets"));
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
// Attach Security Telemetry Logger
app.use(logger_1.telemetryLogger);
// Healthcheck & mode info
app.get('/health', (req, res) => {
    res.json({
        status: 'HEALTHY',
        service: 'SecureLoop Target Application',
        securityMode: config_1.config.securityMode,
        timestamp: new Date().toISOString(),
        revokedTokensCount: config_1.config.revokedTokens.size,
        blockedIpsCount: config_1.config.blockedIps.size
    });
});
// Dynamic mode toggle endpoint for demonstration & automated testing
app.post('/api/admin/toggle-mode', (req, res) => {
    const { mode } = req.body;
    if (mode === 'VULNERABLE' || mode === 'HARDENED') {
        config_1.config.securityMode = mode;
        return res.json({ message: `Security mode changed to ${mode}`, activeMode: config_1.config.securityMode });
    }
    return res.status(400).json({ error: 'Invalid mode. Use VULNERABLE or HARDENED' });
});
// Management endpoints for SOAR Response Actions
app.post('/api/soar/block-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) {
        config_1.config.blockedIps.add(ip);
        return res.json({ message: `IP ${ip} added to SOAR blocklist`, blockedIps: Array.from(config_1.config.blockedIps) });
    }
    return res.status(400).json({ error: 'IP required' });
});
app.post('/api/soar/revoke-token', (req, res) => {
    const { token } = req.body;
    if (token) {
        config_1.config.revokedTokens.add(token);
        return res.json({ message: 'Token revoked by SOAR', tokenSnippet: token.substring(0, 15) });
    }
    return res.status(400).json({ error: 'Token required' });
});
// Mount vulnerability routes
app.use('/api/auth', auth_1.default);
app.use('/api/search', search_1.default);
app.use('/api/users', users_1.default);
app.use('/api/export', export_1.default);
app.use('/api/fetch-url', fetch_1.default);
app.use('/api/upload', upload_1.default);
app.use('/api/debug', secrets_1.default);
// Initialize DB and start server
(0, database_1.initDatabase)().then(() => {
    app.listen(config_1.config.port, () => {
        console.log(`[SecureLoop] Target App running on http://localhost:${config_1.config.port}`);
        console.log(`[SecureLoop] Security Mode: ${config_1.config.securityMode}`);
        console.log(`[SecureLoop] Telemetry Log: ${config_1.config.logFilePath}`);
    });
}).catch(err => {
    console.error('[SecureLoop] Database initialization failed:', err);
    process.exit(1);
});
exports.default = app;
