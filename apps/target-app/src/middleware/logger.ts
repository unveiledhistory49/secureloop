import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';

// Ensure log directory exists
const logDir = path.dirname(config.logFilePath);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

export interface SecurityLogEntry {
  timestamp: string;
  traceId: string;
  requestId: string;
  clientIp: string;
  method: string;
  url: string;
  statusCode?: number;
  durationMs?: number;
  userAgent: string;
  bodyPayload: any;
  headers: Record<string, string>;
  userContext?: {
    userId?: string;
    username?: string;
    role?: string;
  };
  securityEvent?: {
    type: string;
    details: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
}

export function writeSecurityLog(entry: SecurityLogEntry) {
  const line = JSON.stringify(entry) + '\n';
  fs.appendFileSync(config.logFilePath, line, 'utf-8');
}

export const telemetryLogger = (req: Request & { traceId?: string; user?: any }, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  const traceId = (req.headers['x-trace-id'] as string) || `trace-${uuidv4()}`;
  const requestId = (req.headers['x-request-id'] as string) || `req-${uuidv4()}`;
  req.traceId = traceId;

  const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const clientIp = Array.isArray(rawIp) ? rawIp[0] : (rawIp as string).split(',')[0].trim();

  // Check IP blocklist (SOAR response enforcement)
  if (config.blockedIps.has(clientIp)) {
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
      headers: { ...req.headers } as Record<string, string>,
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
    const logEntry: SecurityLogEntry = {
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
