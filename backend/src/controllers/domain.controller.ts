import { Request, Response } from 'express';
import prisma from '../config/database';
import { logger } from '../utils/logger';

/**
 * Domain Controller
 * Handles domain management operations
 */

/**
 * Get all domains for a user
 * GET /api/domains
 */
export async function getDomains(req: Request, res: Response) {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const domains = await prisma.domain.findMany({
      where: { userId },
      include: {
        _count: {
          select: { scans: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(domains);
  } catch (error: any) {
    logger.error('Error fetching domains:', error);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
}

/**
 * Create a new domain
 * POST /api/domains
 */
export async function createDomain(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { name, scanFrequency = 'manual' } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!name) {
      return res.status(400).json({ error: 'Domain name is required' });
    }

    // Validate domain format (basic validation)
    // Allow domains like: unicc.org, sub.domain.com, test-domain.org, wfp.org
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    if (!domainRegex.test(name)) {
      return res.status(400).json({ error: 'Invalid domain format. Please use format like: example.com' });
    }

    // Check if domain already exists for this user
    const existing = await prisma.domain.findFirst({
      where: {
        name,
        userId
      }
    });

    if (existing) {
      return res.status(409).json({ error: 'Domain already exists' });
    }

    const domain = await prisma.domain.create({
      data: {
        name,
        userId,
        scanFrequency,
        active: true
      }
    });

    logger.info(`Domain created: ${name} by user ${userId}`);

    res.status(201).json(domain);
  } catch (error: any) {
    logger.error('Error creating domain:', error.message || error);
    res.status(500).json({ error: error.message || 'Failed to create domain' });
  }
}

/**
 * Get domain by ID
 * GET /api/domains/:id
 */
export async function getDomain(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const domain = await prisma.domain.findUnique({
      where: { id },
      include: {
        scans: {
          take: 10,
          orderBy: { createdAt: 'desc' }
        },
        _count: {
          select: { scans: true }
        }
      }
    });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    if (domain.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(domain);
  } catch (error: any) {
    logger.error('Error fetching domain:', error);
    res.status(500).json({ error: 'Failed to fetch domain' });
  }
}

/**
 * Update domain
 * PUT /api/domains/:id
 */
export async function updateDomain(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;
    const { name, scanFrequency, active } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const domain = await prisma.domain.findUnique({
      where: { id }
    });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    if (domain.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updated = await prisma.domain.update({
      where: { id },
      data: {
        ...(name && { name }),
        ...(scanFrequency && { scanFrequency }),
        ...(active !== undefined && { active })
      }
    });

    logger.info(`Domain updated: ${id}`);

    res.json(updated);
  } catch (error: any) {
    logger.error('Error updating domain:', error);
    res.status(500).json({ error: 'Failed to update domain' });
  }
}

/**
 * Delete domain
 * DELETE /api/domains/:id
 */
export async function deleteDomain(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const domain = await prisma.domain.findUnique({
      where: { id }
    });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    if (domain.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await prisma.domain.delete({
      where: { id }
    });

    logger.info(`Domain deleted: ${id}`);

    res.json({ message: 'Domain deleted successfully' });
  } catch (error: any) {
    logger.error('Error deleting domain:', error);
    res.status(500).json({ error: 'Failed to delete domain' });
  }
}
