import express from 'express';
import cors from 'cors';
import { config } from './config';
import { initDatabase } from './db/database';
import { telemetryLogger } from './middleware/logger';
import authRoutes from './routes/auth';
import searchRoutes from './routes/search';
import usersRoutes from './routes/users';
import exportRoutes from './routes/export';
import fetchRoutes from './routes/fetch';
import uploadRoutes from './routes/upload';
import secretsRoutes from './routes/secrets';

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Attach Security Telemetry Logger
app.use(telemetryLogger);

// Healthcheck & mode info
app.get('/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'SecureLoop Target Application',
    securityMode: config.securityMode,
    timestamp: new Date().toISOString(),
    revokedTokensCount: config.revokedTokens.size,
    blockedIpsCount: config.blockedIps.size
  });
});

// Dynamic mode toggle endpoint for demonstration & automated testing
app.post('/api/admin/toggle-mode', (req, res) => {
  const { mode } = req.body;
  if (mode === 'VULNERABLE' || mode === 'HARDENED') {
    config.securityMode = mode;
    return res.json({ message: `Security mode changed to ${mode}`, activeMode: config.securityMode });
  }
  return res.status(400).json({ error: 'Invalid mode. Use VULNERABLE or HARDENED' });
});

// Management endpoints for SOAR Response Actions
app.post('/api/soar/block-ip', (req, res) => {
  const { ip } = req.body;
  if (ip) {
    config.blockedIps.add(ip);
    return res.json({ message: `IP ${ip} added to SOAR blocklist`, blockedIps: Array.from(config.blockedIps) });
  }
  return res.status(400).json({ error: 'IP required' });
});

app.post('/api/soar/revoke-token', (req, res) => {
  const { token } = req.body;
  if (token) {
    config.revokedTokens.add(token);
    return res.json({ message: 'Token revoked by SOAR', tokenSnippet: token.substring(0, 15) });
  }
  return res.status(400).json({ error: 'Token required' });
});

// Mount vulnerability routes
app.use('/api/auth', authRoutes);
app.use('/api/search', searchRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/export', exportRoutes);
app.use('/api/fetch-url', fetchRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/debug', secretsRoutes);

// Initialize DB and start server
initDatabase().then(() => {
  app.listen(config.port, () => {
    console.log(`[SecureLoop] Target App running on http://localhost:${config.port}`);
    console.log(`[SecureLoop] Security Mode: ${config.securityMode}`);
    console.log(`[SecureLoop] Telemetry Log: ${config.logFilePath}`);
  });
}).catch(err => {
  console.error('[SecureLoop] Database initialization failed:', err);
  process.exit(1);
});

export default app;
