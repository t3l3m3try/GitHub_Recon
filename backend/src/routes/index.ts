import { Router } from 'express';
import * as domainController from '../controllers/domain.controller';
import * as scanController from '../controllers/scan.controller';
import * as findingsController from '../controllers/findings.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

/**
 * API Routes
 */

// Health check
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Domain routes
router.get('/domains', authenticateToken, domainController.getDomains);
router.post('/domains', authenticateToken, domainController.createDomain);
router.get('/domains/:id', authenticateToken, domainController.getDomain);
router.put('/domains/:id', authenticateToken, domainController.updateDomain);
router.delete('/domains/:id', authenticateToken, domainController.deleteDomain);

// Scan routes
router.get('/scans', authenticateToken, scanController.getScans);
router.post('/scans', authenticateToken, scanController.createScan);
router.get('/scans/:id', authenticateToken, scanController.getScan);
router.get('/scans/:id/findings', authenticateToken, scanController.getScanFindings);
router.delete('/scans/:id', authenticateToken, scanController.cancelScan);

// Findings routes
router.get('/findings', authenticateToken, findingsController.getFindings);
router.get('/findings/stats', authenticateToken, findingsController.getStatistics);
router.get('/findings/:id', authenticateToken, findingsController.getFinding);
router.put('/findings/:id', authenticateToken, findingsController.updateFinding);
router.post('/findings/bulk-update', authenticateToken, findingsController.bulkUpdateFindings);
router.delete('/findings/:id', authenticateToken, findingsController.deleteFinding);

export default router;
