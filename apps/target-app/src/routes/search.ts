import { Router, Request, Response } from 'express';
import { db } from '../db/database';
import { config } from '../config';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1190 SQL Injection endpoint
router.get('/', (req: Request, res: Response) => {
  const query = req.query.q as string || '';

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: Raw SQL String Concatenation (T1190)
    const sql = `SELECT * FROM products WHERE category = '${query}' OR name LIKE '%${query}%'`;
    
    db.all(sql, (err, rows) => {
      if (err) {
        writeSecurityLog({
          timestamp: new Date().toISOString(),
          traceId: (req as any).traceId || 'unknown',
          requestId: `req-${Date.now()}`,
          clientIp: req.ip || '127.0.0.1',
          method: req.method,
          url: req.originalUrl,
          statusCode: 500,
          userAgent: req.headers['user-agent'] || '',
          bodyPayload: {},
          headers: req.headers as Record<string, string>,
          securityEvent: {
            type: 'SQL_ERROR_EXPLOIT',
            details: `SQL error triggered by query: ${query}. Error: ${err.message}`,
            severity: 'HIGH'
          }
        });
        return res.status(500).json({ error: 'Database query execution error', details: err.message, query: sql });
      }
      return res.json({ mode: 'VULNERABLE', results: rows });
    });
  } else {
    // HARDENED MODE: Parameterized Query
    const sql = `SELECT * FROM products WHERE category = ? OR name LIKE ?`;
    const searchPattern = `%${query}%`;
    
    db.all(sql, [query, searchPattern], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      return res.json({ mode: 'HARDENED', results: rows });
    });
  }
});

export default router;
