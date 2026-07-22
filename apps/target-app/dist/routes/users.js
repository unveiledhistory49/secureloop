"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const database_1 = require("../db/database");
const config_1 = require("../config");
const auth_1 = require("../middleware/auth");
const logger_1 = require("../middleware/logger");
const router = (0, express_1.Router)();
// T1068 IDOR / Privilege Escalation
const handleRoleUpdate = (req, res) => {
    const targetUserId = req.params.id;
    const { newRole } = req.body;
    const currentUser = req.user;
    if (config_1.config.securityMode === 'VULNERABLE') {
        // VULNERABILITY: No authorization check on who can elevate role (IDOR / PrivEsc)
        database_1.db.run('UPDATE users SET role = ? WHERE id = ?', [newRole, targetUserId], function (err) {
            if (err) {
                return res.status(500).json({ error: 'Database update failed' });
            }
            (0, logger_1.writeSecurityLog)({
                timestamp: new Date().toISOString(),
                traceId: req.traceId || 'unknown',
                requestId: `req-${Date.now()}`,
                clientIp: req.ip || '127.0.0.1',
                method: req.method,
                url: req.originalUrl,
                statusCode: 200,
                userAgent: req.headers['user-agent'] || '',
                bodyPayload: req.body,
                headers: req.headers,
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
    }
    else {
        // HARDENED MODE: Require ADMIN role
        if (currentUser.role !== 'ADMIN') {
            return res.status(403).json({ error: 'Forbidden: Privilege escalation attempt blocked. ADMIN role required.' });
        }
        database_1.db.run('UPDATE users SET role = ? WHERE id = ?', [newRole, targetUserId], function (err) {
            if (err)
                return res.status(500).json({ error: 'Database update failed' });
            return res.json({ message: 'Role updated by Admin', targetUserId, newRole, mode: 'HARDENED' });
        });
    }
};
router.put('/:id/role', auth_1.authenticateToken, handleRoleUpdate);
router.post('/:id/role', auth_1.authenticateToken, handleRoleUpdate);
// GET user details
router.get('/:id', auth_1.authenticateToken, (req, res) => {
    const targetUserId = req.params.id;
    const currentUser = req.user;
    if (config_1.config.securityMode === 'VULNERABLE') {
        // IDOR: Any user can read any other user's record including API key
        database_1.db.get('SELECT id, username, role, email, api_key FROM users WHERE id = ?', [targetUserId], (err, user) => {
            if (err || !user)
                return res.status(404).json({ error: 'User not found' });
            return res.json(user);
        });
    }
    else {
        // HARDENED MODE: Self or ADMIN only
        if (currentUser.id !== targetUserId && currentUser.role !== 'ADMIN') {
            return res.status(403).json({ error: 'Forbidden: Cannot view other users records' });
        }
        database_1.db.get('SELECT id, username, role, email FROM users WHERE id = ?', [targetUserId], (err, user) => {
            if (err || !user)
                return res.status(404).json({ error: 'User not found' });
            return res.json(user);
        });
    }
});
exports.default = router;
