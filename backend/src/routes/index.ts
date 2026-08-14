import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import * as domainController from '../controllers/domain.controller';
import * as scanController from '../controllers/scan.controller';
import * as findingsController from '../controllers/findings.controller';
import * as queriesController from '../controllers/queries.controller';
import * as patternsController from '../controllers/patterns.controller';
import * as authController from '../controllers/auth.controller';
import * as adminController from '../controllers/admin.controller';
import * as twoFactorController from '../controllers/twofactor.controller';
import {
  authenticateToken,
  blockIfPasswordChangeRequired,
  blockIfTwoFactorSetupRequired,
  requirePermission,
  requireSuperAdmin,
} from '../middleware/auth.middleware';
import { PERMISSIONS } from '../utils/permissions';

const router = Router();

/**
 * API Routes
 *
 * Everything except /health and the login/refresh pair requires a valid access
 * token. Each protected route additionally declares the permission it needs, so
 * authorization is visible here rather than buried in the controllers.
 */

/**
 * Brute-force protection on credential endpoints, layered on top of the
 * per-account lockout in auth.service.
 *
 * Only FAILED attempts count. Successful sign-ins are skipped so that several
 * legitimate users behind one office IP can never lock each other out — the
 * limiter targets guessing (many failures from one source) rather than volume.
 */
const loginLimiter = rateLimit({
  windowMs: Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT_MAX) || 30,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many failed login attempts from this address. Try again later.' },
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again later.' },
});

// Health check
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Auth (public) ──────────────────────────────────────────────────────────
router.post('/auth/login', loginLimiter, authController.login);
router.post('/auth/refresh', refreshLimiter, authController.refresh);
router.get('/auth/password-policy', authController.passwordPolicy);
router.get('/auth/setup-status', authController.setupStatus);
router.post('/auth/setup', loginLimiter, authController.completeSetup);
// Completes a login bounced to the 2FA challenge — no access token yet, so
// this has to stay public. loginLimiter caps guessing the code just like it
// caps guessing the password.
router.post('/auth/2fa/verify', loginLimiter, authController.verifyTwoFactor);

// ── Auth (authenticated; exempt from the must-change-password block) ───────
router.post('/auth/logout', authenticateToken, authController.logout);
router.get('/auth/me', authenticateToken, authController.me);
router.post('/auth/change-password', authenticateToken, authController.changePassword);

// ── Auth (authenticated; self-service 2FA enrollment) ───────────────────────
// Exempt from blockIfTwoFactorSetupRequired — this is where that requirement
// gets satisfied — but a pending password change must still be resolved first.
const selfServiceAuth = [authenticateToken, blockIfPasswordChangeRequired];
router.get('/auth/2fa/status', selfServiceAuth, twoFactorController.status);
router.post('/auth/2fa/setup', selfServiceAuth, loginLimiter, twoFactorController.setup);
router.post('/auth/2fa/enable', selfServiceAuth, loginLimiter, twoFactorController.enable);
router.post('/auth/2fa/disable', selfServiceAuth, loginLimiter, twoFactorController.disable);
router.post(
  '/auth/2fa/recovery-codes/regenerate',
  selfServiceAuth, loginLimiter, twoFactorController.regenerateRecoveryCodes
);

// Everything below additionally requires that no password change, and no
// mandated 2FA enrollment, is pending.
const auth = [authenticateToken, blockIfPasswordChangeRequired, blockIfTwoFactorSetupRequired];

// ── Account (self-service) ───────────────────────────────────────────────
router.put('/auth/profile', auth, authController.updateProfile);
router.get('/auth/permissions', auth, authController.myPermissions);

// ── Domains ────────────────────────────────────────────────────────────────
router.get('/domains', auth, requirePermission(PERMISSIONS.DOMAIN_READ), domainController.getDomains);
router.post('/domains', auth, requirePermission(PERMISSIONS.DOMAIN_WRITE), domainController.createDomain);
router.get('/domains/:id', auth, requirePermission(PERMISSIONS.DOMAIN_READ), domainController.getDomain);
router.put('/domains/:id', auth, requirePermission(PERMISSIONS.DOMAIN_WRITE), domainController.updateDomain);
router.delete('/domains/:id', auth, requirePermission(PERMISSIONS.DOMAIN_DELETE), domainController.deleteDomain);

// ── Scans ──────────────────────────────────────────────────────────────────
router.get('/scans', auth, requirePermission(PERMISSIONS.DOMAIN_READ), scanController.getScans);
router.post('/scans', auth, requirePermission(PERMISSIONS.SCAN_RUN), scanController.createScan);
router.get('/scans/:id', auth, requirePermission(PERMISSIONS.DOMAIN_READ), scanController.getScan);
router.get('/scans/:id/findings', auth, requirePermission(PERMISSIONS.FINDING_READ), scanController.getScanFindings);
router.delete('/scans/:id', auth, requirePermission(PERMISSIONS.SCAN_CANCEL), scanController.cancelScan);

// ── Findings ───────────────────────────────────────────────────────────────
router.get('/findings', auth, requirePermission(PERMISSIONS.FINDING_READ), findingsController.getFindings);
router.get('/findings/stats', auth, requirePermission(PERMISSIONS.FINDING_READ), findingsController.getStatistics);
router.get('/findings/export', auth, requirePermission(PERMISSIONS.FINDING_EXPORT), findingsController.exportFindings);
router.get('/findings/:id', auth, requirePermission(PERMISSIONS.FINDING_READ), findingsController.getFinding);
router.put('/findings/:id', auth, requirePermission(PERMISSIONS.FINDING_UPDATE), findingsController.updateFinding);
router.post('/findings/bulk-update', auth, requirePermission(PERMISSIONS.FINDING_UPDATE), findingsController.bulkUpdateFindings);
router.delete('/findings/:id', auth, requirePermission(PERMISSIONS.FINDING_DELETE), findingsController.deleteFinding);

// ── Query catalog ──────────────────────────────────────────────────────────
router.get('/queries', auth, requirePermission(PERMISSIONS.QUERY_READ), queriesController.getQueries);
router.put('/queries', auth, requirePermission(PERMISSIONS.QUERY_WRITE), queriesController.updateQueries);
router.post('/queries/reset', auth, requirePermission(PERMISSIONS.QUERY_WRITE), queriesController.resetQueries);

// ── Detection patterns (read-only) ──────────────────────────────────────────
router.get('/patterns', auth, requirePermission(PERMISSIONS.QUERY_READ), patternsController.getPatterns);

// ── Administration ─────────────────────────────────────────────────────────
router.get('/admin/meta', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.getMeta);

router.get('/admin/organizations', auth, requirePermission(PERMISSIONS.ORG_MANAGE), adminController.getOrganizations);
router.post('/admin/organizations', auth, requireSuperAdmin, adminController.createOrganization);
router.put('/admin/organizations/:id', auth, requirePermission(PERMISSIONS.ORG_MANAGE), adminController.updateOrganization);
router.delete('/admin/organizations/:id', auth, requireSuperAdmin, adminController.deleteOrganization);

router.get('/admin/users', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.getUsers);
router.post('/admin/users', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.createUser);
router.put('/admin/users/:id', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.updateUser);
router.delete('/admin/users/:id', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.deleteUser);
router.post('/admin/users/:id/reset-password', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.resetUserPassword);
router.post('/admin/users/:id/unlock', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.unlockUser);
router.post('/admin/users/:id/2fa/disable', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.disableTwoFactorForUser);
router.post('/admin/users/:id/2fa/reset', auth, requirePermission(PERMISSIONS.USER_MANAGE), adminController.resetTwoFactorForUser);

router.get('/admin/audit', auth, requireSuperAdmin, adminController.getAuditLog);

export default router;
