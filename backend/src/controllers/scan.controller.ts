import { Request, Response } from 'express';
import prisma from '../config/database';
import ScannerService from '../services/scanner.service';
import { logger } from '../utils/logger';

/**
 * Scan Controller
 * Handles scan-related operations with proper stop/re-run support
 */

/**
 * Create and initiate a new scan
 * POST /api/scans
 */
export async function createScan(req: Request, res: Response) {
  try {
    const { domainId } = req.body;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Get domain
    const domain = await prisma.domain.findUnique({
      where: { id: domainId }
    });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    // Check if domain belongs to user
    if (domain.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check if there's already a running scan for this domain
    const runningScan = await prisma.scan.findFirst({
      where: {
        domainId,
        status: { in: ['QUEUED', 'RUNNING'] }
      }
    });

    if (runningScan) {
      return res.status(409).json({
        error: 'A scan is already running for this domain. Cancel it first or wait for completion.',
        runningScanId: runningScan.id
      });
    }

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        domainId,
        userId,
        status: 'QUEUED'
      }
    });

    logger.info(`Scan ${scan.id} created for domain: ${domain.name}`);

    // Start scan immediately in background
    setImmediate(async () => {
      try {
        const scanner = new ScannerService(process.env.GITHUB_TOKEN || '');
        await scanner.executeScan(scan.id, domain.name, {
          includeCode: true,
          includeCommits: true,
          includeIssues: true
        });
        logger.info(`Scan ${scan.id} completed successfully`);
      } catch (error: any) {
        logger.error(`Scan ${scan.id} failed:`, error);
      }
    });

    res.status(201).json(scan);
  } catch (error: any) {
    logger.error('Error creating scan:', error);
    res.status(500).json({ error: 'Failed to create scan' });
  }
}

/**
 * Get all scans for a user
 * GET /api/scans
 */
export async function getScans(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { page = 1, limit = 20, domainId, status } = req.query;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const where: any = { userId };

    if (domainId) {
      where.domainId = domainId as string;
    }

    if (status) {
      where.status = status as string;
    }

    const skip = (Number(page) - 1) * Number(limit);

    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where,
        include: {
          domain: true
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: Number(limit)
      }),
      prisma.scan.count({ where })
    ]);

    // Annotate with live running status and parsed progress
    const annotatedScans = scans.map(scan => {
      const isActive = ScannerService.isRunning(scan.id);
      let progress = null;
      if (scan.errorMessage?.startsWith('PROGRESS:')) {
        try {
          progress = JSON.parse(scan.errorMessage.substring(9));
        } catch { /* ignore parse errors */ }
      }
      return {
        ...scan,
        isActivelyRunning: isActive,
        progress,
        // Clear errorMessage when it's just progress data (not a real error)
        errorMessage: scan.errorMessage?.startsWith('PROGRESS:') ? null : scan.errorMessage,
      };
    });

    res.json({
      scans: annotatedScans,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / Number(limit))
      }
    });
  } catch (error: any) {
    logger.error('Error fetching scans:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
}

/**
 * Get scan by ID
 * GET /api/scans/:id
 */
export async function getScan(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scan = await prisma.scan.findUnique({
      where: { id },
      include: {
        domain: true,
        findings: {
          take: 10,
          orderBy: { score: 'desc' }
        }
      }
    });

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Add live status and parsed progress
    let progress = null;
    if (scan.errorMessage?.startsWith('PROGRESS:')) {
      try {
        progress = JSON.parse(scan.errorMessage.substring(9));
      } catch { /* ignore */ }
    }
    const result = {
      ...scan,
      isActivelyRunning: ScannerService.isRunning(scan.id),
      progress,
      errorMessage: scan.errorMessage?.startsWith('PROGRESS:') ? null : scan.errorMessage,
    };

    res.json(result);
  } catch (error: any) {
    logger.error('Error fetching scan:', error);
    res.status(500).json({ error: 'Failed to fetch scan' });
  }
}

/**
 * Get scan findings
 * GET /api/scans/:id/findings
 */
export async function getScanFindings(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;
    const {
      page = 1,
      limit = 50,
      criticality,
      type,
      verified,
      falsePositive
    } = req.query;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Verify scan belongs to user
    const scan = await prisma.scan.findUnique({
      where: { id }
    });

    if (!scan || scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const where: any = { scanId: id };

    if (criticality) {
      where.criticality = criticality as string;
    }

    if (type) {
      where.secrets = { some: { type: type as string } };
    }

    if (verified !== undefined) {
      where.verified = verified === 'true';
    }

    if (falsePositive !== undefined) {
      where.falsePositive = falsePositive === 'true';
    }

    const skip = (Number(page) - 1) * Number(limit);

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        orderBy: { score: 'desc' },
        skip,
        take: Number(limit)
      }),
      prisma.finding.count({ where })
    ]);

    res.json({
      findings,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / Number(limit))
      }
    });
  } catch (error: any) {
    logger.error('Error fetching scan findings:', error);
    res.status(500).json({ error: 'Failed to fetch findings' });
  }
}

/**
 * Cancel a scan
 * DELETE /api/scans/:id
 */
export async function cancelScan(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scan = await prisma.scan.findUnique({
      where: { id }
    });

    if (!scan || scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    if (scan.status !== 'QUEUED' && scan.status !== 'RUNNING') {
      return res.status(400).json({ error: 'Cannot cancel a scan that is not queued or running' });
    }

    const scanner = new ScannerService(process.env.GITHUB_TOKEN || '');
    await scanner.cancelScan(id);

    res.json({ message: 'Scan cancelled successfully' });
  } catch (error: any) {
    logger.error('Error cancelling scan:', error);
    res.status(500).json({ error: 'Failed to cancel scan' });
  }
}
