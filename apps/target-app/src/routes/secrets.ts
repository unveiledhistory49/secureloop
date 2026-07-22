import { Router, Request, Response } from 'express';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1552 Unsecured Credentials
router.get('/config', (req: Request, res: Response) => {
  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: Exposing sensitive configuration secrets in API response (T1552)
    writeSecurityLog({
      timestamp: new Date().toISOString(),
      traceId: (req as any).traceId || 'unknown',
      requestId: `req-${Date.now()}`,
      clientIp: req.ip || '127.0.0.1',
      method: req.method,
      url: req.originalUrl,
      statusCode: 200,
      userAgent: req.headers['user-agent'] || '',
      bodyPayload: {},
      headers: req.headers as Record<string, string>,
      securityEvent: {
        type: 'SECRET_LEAKAGE_EXPLOIT',
        details: 'VULNERABLE MODE: Debug endpoint exposed internal JWT secrets and database connection strings',
        severity: 'HIGH'
      }
    });

    return res.json({
      environment: 'development',
      jwtSecret: config.jwtSecret,
      databaseUrl: 'sqlite://root:SuperSecretDbPass2026@/root/secureloop/apps/target-app/secureloop.db',
      awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
      awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      mode: 'VULNERABLE'
    });
  } else {
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

export default router;
