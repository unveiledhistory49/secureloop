import { Router, Request, Response } from 'express';
import { exec } from 'child_process';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1059.004 Command Injection endpoint
router.post('/', (req: Request, res: Response) => {
  const { filename, format } = req.body;

  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: Shell command string concatenation (T1059.004)
    const cmd = `echo "Exporting data to ${filename}" && echo "Format: ${format || 'txt'}"`;

    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        writeSecurityLog({
          timestamp: new Date().toISOString(),
          traceId: (req as any).traceId || 'unknown',
          requestId: `req-${Date.now()}`,
          clientIp: req.ip || '127.0.0.1',
          method: req.method,
          url: req.originalUrl,
          statusCode: 500,
          userAgent: req.headers['user-agent'] || '',
          bodyPayload: req.body,
          headers: req.headers as Record<string, string>,
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
  } else {
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

export default router;
