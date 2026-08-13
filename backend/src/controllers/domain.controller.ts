import { Request, Response } from 'express';
import prisma from '../config/database';
import { scopeFor } from '../middleware/auth.middleware';
import { logger } from '../utils/logger';

/**
 * Domain Controller
 *
 * Domains belong to an organization, not to the individual who created it, so
 * every member of that organization sees them. The super admin is unscoped.
 */

/**
 * Get all domains visible to the requester
 * GET /api/domains
 */
export async function getDomains(req: Request, res: Response) {
  try {
    const scope = scopeFor(req);

    const domains = await prisma.domain.findMany({
      where: scope.domain,
      include: {
        _count: { select: { scans: true } },
        organization: { select: { id: true, name: true, slug: true } },
        user: { select: { id: true, username: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json(domains);
  } catch (error: any) {
    logger.error('Error fetching domains:', error);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
}

/**
 * Create a new domain in the requester's organization
 * POST /api/domains
 */
export async function createDomain(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { name, scanFrequency = 'manual', orgId: requestedOrgId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!name) {
      return res.status(400).json({ error: 'Domain name is required' });
    }

    // Validate domain format (basic validation)
    // Allow domains like: example.com, sub.domain.com, test-domain.org
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    if (!domainRegex.test(name)) {
      return res.status(400).json({ error: 'Invalid domain format. Please use format like: example.com' });
    }

    // A super admin has no organization of their own, so they must say which
    // tenant the domain belongs to; everyone else gets their own.
    const orgId = req.user?.isSuperAdmin ? (requestedOrgId ? String(requestedOrgId) : null) : req.user?.orgId ?? null;

    if (!orgId) {
      return res.status(400).json({
        error: req.user?.isSuperAdmin
          ? 'Select an organization for this domain'
          : 'Your account is not assigned to an organization',
      });
    }

    const organization = await prisma.organization.findUnique({
      where: { id: orgId },
      include: { _count: { select: { domains: true } } },
    });

    if (!organization) {
      return res.status(404).json({ error: 'Organization not found' });
    }

    if (organization._count.domains >= organization.maxDomains) {
      return res.status(409).json({
        error: `Organization "${organization.name}" has reached its limit of ${organization.maxDomains} domains`,
      });
    }

    const existing = await prisma.domain.findFirst({ where: { name, orgId } });
    if (existing) {
      return res.status(409).json({ error: 'This organization is already monitoring that domain' });
    }

    const domain = await prisma.domain.create({
      data: { name, orgId, userId, scanFrequency, active: true },
    });

    logger.info(`Domain created: ${name} in ${organization.name} by ${req.user?.email}`);

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
    const scope = scopeFor(req);

    // Scope is part of the lookup, so another tenant's id is simply not found.
    const domain = await prisma.domain.findFirst({
      where: { id, ...scope.domain },
      include: {
        scans: { take: 10, orderBy: { createdAt: 'desc' } },
        organization: { select: { id: true, name: true, slug: true } },
        _count: { select: { scans: true } },
      },
    });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
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
    const { name, scanFrequency, active } = req.body;
    const scope = scopeFor(req);

    const domain = await prisma.domain.findFirst({ where: { id, ...scope.domain } });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    if (name && name !== domain.name) {
      const clash = await prisma.domain.findFirst({
        where: { name, orgId: domain.orgId, id: { not: id } },
      });
      if (clash) {
        return res.status(409).json({ error: 'This organization is already monitoring that domain' });
      }
    }

    const updated = await prisma.domain.update({
      where: { id },
      data: {
        ...(name && { name }),
        ...(scanFrequency && { scanFrequency }),
        ...(active !== undefined && { active }),
      },
    });

    logger.info(`Domain updated: ${id} by ${req.user?.email}`);

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
    const scope = scopeFor(req);

    const domain = await prisma.domain.findFirst({ where: { id, ...scope.domain } });

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    await prisma.domain.delete({ where: { id } });

    logger.info(`Domain deleted: ${domain.name} by ${req.user?.email}`);

    res.json({ message: 'Domain deleted successfully' });
  } catch (error: any) {
    logger.error('Error deleting domain:', error);
    res.status(500).json({ error: 'Failed to delete domain' });
  }
}
