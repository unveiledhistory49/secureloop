import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { writeSecurityLog } from './logger';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    username: string;
    role: string;
  };
  traceId?: string;
}

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required: missing token' });
  }

  // Check if token is revoked in SOAR engine
  if (config.revokedTokens.has(token)) {
    return res.status(401).json({ error: 'Token has been revoked by security response' });
  }

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABLE MODE: Flawed JWT Verification
    try {
      // Decode header to check alg
      const decodedHeader: any = jwt.decode(token, { complete: true });
      if (decodedHeader && decodedHeader.header && decodedHeader.header.alg === 'none') {
        // VULNERABILITY: Accepting unsigned 'none' algorithm JWT (T1078)
        const payload: any = jwt.decode(token);
        req.user = payload;
        
        writeSecurityLog({
          timestamp: new Date().toISOString(),
          traceId: req.traceId || 'unknown',
          requestId: `req-${Date.now()}`,
          clientIp: req.ip || '127.0.0.1',
          method: req.method,
          url: req.originalUrl,
          userAgent: req.headers['user-agent'] || '',
          bodyPayload: req.body,
          headers: req.headers as Record<string, string>,
          securityEvent: {
            type: 'JWT_ALG_NONE_EXPLOIT',
            details: `VULNERABLE MODE: Accepted JWT with alg=none for user ${payload?.username}`,
            severity: 'HIGH'
          }
        });

        return next();
      }

      // Default decode without strict signature check in vulnerable mode
      const decoded: any = jwt.verify(token, config.jwtSecret);
      req.user = decoded;
      return next();
    } catch (err: any) {
      // In vulnerable mode, fall back to unsafe decode if secret mismatch
      const unsafeDecoded: any = jwt.decode(token);
      if (unsafeDecoded) {
        req.user = unsafeDecoded;
        return next();
      }
      return res.status(403).json({ error: 'Invalid token' });
    }
  } else {
    // HARDENED MODE: Strict verification
    try {
      const decoded = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }) as any;
      req.user = decoded;
      return next();
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token or algorithm mismatch' });
    }
  }
};
