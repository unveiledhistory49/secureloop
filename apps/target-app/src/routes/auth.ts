import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { db } from '../db/database';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1110 Brute Force & Login
router.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user: any) => {
    if (err || !user || user.password !== password) {
      // Log failed login attempt for T1110 detection
      writeSecurityLog({
        timestamp: new Date().toISOString(),
        traceId: (req as any).traceId || 'unknown',
        requestId: `req-${Date.now()}`,
        clientIp: req.ip || '127.0.0.1',
        method: req.method,
        url: req.originalUrl,
        statusCode: 401,
        userAgent: req.headers['user-agent'] || '',
        bodyPayload: { username, password: '***' },
        headers: req.headers as Record<string, string>,
        securityEvent: {
          type: 'AUTH_FAILURE',
          details: `Failed authentication attempt for username: ${username}`,
          severity: 'MEDIUM'
        }
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      config.jwtSecret,
      { expiresIn: '2h' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  });
});

// Endpoint to forge algorithmic vulnerability tokens in VULNERABLE mode (T1078)
router.post('/forge-token', (req: Request, res: Response) => {
  const { username, role, alg } = req.body;

  if (config.securityMode === 'VULNERABLE' && alg === 'none') {
    // Manually construct alg: none header
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ id: 'usr-999', username: username || 'hacker', role: role || 'ADMIN' })).toString('base64url');
    const forgedToken = `${header}.${payload}.`;
    return res.json({ token: forgedToken, note: 'VULNERABLE MODE: Forged alg=none JWT issued' });
  }

  // Standard token
  const token = jwt.sign({ id: 'usr-002', username: username || 'alice', role: role || 'USER' }, config.jwtSecret);
  return res.json({ token });
});

export default router;
