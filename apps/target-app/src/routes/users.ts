import { Router, Response } from 'express';
import { db } from '../db/database';
import { config } from '../config';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { writeSecurityLog } from '../middleware/logger';

const router = Router();

// T1068 IDOR / Privilege Escalation
const handleRoleUpdate = (req: AuthenticatedRequest, res: Response) => {
  const targetUserId = req.params.id;
  const { newRole } = req.body;
  const currentUser = req.user!;

  if (config.securityMode === 'VULNERABLE') {
    // VULNERABILITY: No authorization check on who can elevate role (IDOR / PrivEsc)
    db.run('UPDATE users SET role = ? WHERE id = ?', [newRole, targetUserId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database update failed' });
      }

      writeSecurityLog({
        timestamp: new Date().toISOString(),
        traceId: req.traceId || 'unknown',
        requestId: `req-${Date.now()}`,
        clientIp: req.ip || '127.0.0.1',
        method: req.method,
        url: req.originalUrl,
        statusCode: 200,
        userAgent: req.headers['user-agent'] || '',
        bodyPayload: req.body,
        headers: req.headers as Record<string, string>,
        userContext: {
          userId: currentUser.id,
          username: currentUser.username,
          role: currentUser.role
        },
        securityEvent: {
          type: 'PRIVILEGE_ESCALATION_DETECTED',
          details: `User ${currentUser.username} (${currentUser.role}) changed role of target user ${targetUserId} to ${newRole}`,
          severity: 'HIGH'
        }
      });

      return res.json({
        message: 'Role updated successfully',
        targetUserId,
        newRole,
        mode: 'VULNERABLE'
      });
    });
  } else {
    // HARDENED MODE: Require ADMIN role
    if (currentUser.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Privilege escalation attempt blocked. ADMIN role required.' });
    }

    db.run('UPDATE users SET role = ? WHERE id = ?', [newRole, targetUserId], function(err) {
      if (err) return res.status(500).json({ error: 'Database update failed' });
      return res.json({ message: 'Role updated by Admin', targetUserId, newRole, mode: 'HARDENED' });
    });
  }
};

router.put('/:id/role', authenticateToken, handleRoleUpdate);
router.post('/:id/role', authenticateToken, handleRoleUpdate);

// GET user details
router.get('/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
  const targetUserId = req.params.id;
  const currentUser = req.user!;

  if (config.securityMode === 'VULNERABLE') {
    // IDOR: Any user can read any other user's record including API key
    db.get('SELECT id, username, role, email, api_key FROM users WHERE id = ?', [targetUserId], (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      return res.json(user);
    });
  } else {
    // HARDENED MODE: Self or ADMIN only
    if (currentUser.id !== targetUserId && currentUser.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Cannot view other users records' });
    }
    db.get('SELECT id, username, role, email FROM users WHERE id = ?', [targetUserId], (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      return res.json(user);
    });
  }
});

export default router;
