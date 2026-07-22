import { Router, Request, Response } from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1041 / SSRF External URL fetcher
router.get('/', (req: Request, res: Response) => {
  const targetUrl = req.query.url as string;

  if (!targetUrl) {
    return res.status(400).json({ error: 'URL query parameter required' });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: Arbitrary outbound HTTP fetch (SSRF to local/cloud metadata)
    const client = parsedUrl.protocol === 'https:' ? https : http;

    const request = client.get(targetUrl, (response) => {
      let data = '';
      response.on('data', (chunk) => { data += chunk; });
      response.on('end', () => {
        if (res.headersSent) return;
        // Detect metadata or internal loopback targets for logging
        if (targetUrl.includes('169.254.169.254') || targetUrl.includes('127.0.0.1') || targetUrl.includes('localhost')) {
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
      if (res.headersSent) return;
      return res.status(500).json({ error: 'Failed to fetch target URL', details: err.message, mode: 'VULNERABLE' });
    });

    request.setTimeout(3000, () => {
      request.destroy();
      if (!res.headersSent) {
        return res.status(504).json({ error: 'Request timeout fetching URL' });
      }
    });
  } else {
    // HARDENED MODE: Block private IPs, RFC1918, localhost & cloud metadata
    const hostname = parsedUrl.hostname.toLowerCase();

    const isPrivate = 
      hostname === 'localhost' ||
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

export default router;
