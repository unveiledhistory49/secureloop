import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

const uploadDir = path.resolve(__dirname, '../../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Seed a sample file
fs.writeFileSync(path.join(uploadDir, 'sample.txt'), 'SecureLoop Upload Directory Sample File\n');

// Path Traversal / Arbitrary File Read endpoint
router.get('/preview', (req: Request, res: Response) => {
  const fileParam = req.query.file as string;

  if (!fileParam) {
    return res.status(400).json({ error: 'File parameter required' });
  }

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: Path Traversal (Arbitrary File Read)
    const targetPath = path.resolve(uploadDir, fileParam);

    if (fileParam.includes('..') || fileParam.includes('/etc/')) {
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
          type: 'PATH_TRAVERSAL_ATTEMPT',
          details: `Path traversal payload requested: ${fileParam}`,
          severity: 'HIGH'
        }
      });
    }

    try {
      if (fs.existsSync(targetPath)) {
        const content = fs.readFileSync(targetPath, 'utf-8');
        return res.json({ filename: fileParam, contentSnippet: content.substring(0, 1000), mode: 'VULNERABLE' });
      } else {
        return res.status(404).json({ error: 'File not found', pathAttempted: targetPath });
      }
    } catch (err: any) {
      return res.status(500).json({ error: 'Error reading file', details: err.message });
    }
  } else {
    // HARDENED MODE: Sanitize file path using path.basename
    const safeFilename = path.basename(fileParam);
    const safePath = path.join(uploadDir, safeFilename);

    try {
      if (fs.existsSync(safePath)) {
        const content = fs.readFileSync(safePath, 'utf-8');
        return res.json({ filename: safeFilename, contentSnippet: content.substring(0, 1000), mode: 'HARDENED' });
      } else {
        return res.status(404).json({ error: 'File not found in upload sandbox' });
      }
    } catch (err: any) {
      return res.status(500).json({ error: 'Error reading file' });
    }
  }
});

export default router;
