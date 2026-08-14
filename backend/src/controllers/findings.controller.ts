import { Request, Response } from 'express';
import prisma from '../config/database';
import { scopeFor } from '../middleware/auth.middleware';
import { logger } from '../utils/logger';
import { getMacroCategory } from '../utils/macroCategories';
import { SECRET_PATTERNS } from '../utils/patterns';

// Cache for mapping macro category IDs to active secret types
let macroCategoryTypesMap: Record<string, string[]> | null = null;

function getMacroCategoryTypes(categoryId: string): string[] {
  if (!macroCategoryTypesMap) {
    macroCategoryTypesMap = {};
    const allTypes = new Set<string>();
    
    // Collect all unique types from SECRET_PATTERNS
    for (const p of SECRET_PATTERNS) {
      allTypes.add(p.type);
    }
    // Add additional runtime types that are dynamically discovered
    allTypes.add('EMAIL');
    allTypes.add('CREDENTIAL_PAIR');
    
    // Group them by their macro category
    for (const type of allTypes) {
      const cat = getMacroCategory(type);
      if (!macroCategoryTypesMap[cat.id]) {
        macroCategoryTypesMap[cat.id] = [];
      }
      macroCategoryTypesMap[cat.id].push(type);
    }
  }
  return macroCategoryTypesMap[categoryId] || [];
}

/**
 * Findings Controller
 * Handles finding-related operations
 */

/**
 * Get all findings for a user
 * GET /api/findings
 */
export async function getFindings(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const {
      page = 1,
      limit = 50,
      criticality,
      type,
      repository,
      domain,
      verified,
      falsePositive,
      search,
      scanId
    } = req.query;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scope = scopeFor(req);
    const where: any = { ...scope.finding };

    if (criticality) {
      where.criticality = criticality as string;
    }

    if (type) {
      const typeStr = type as string;
      if (typeStr.startsWith('MACRO_')) {
        const categoryId = typeStr.replace('MACRO_', '');
        const matchingTypes = getMacroCategoryTypes(categoryId);
        
        if (matchingTypes.length > 0) {
          where.primaryType = { in: matchingTypes };
        } else {
          where.primaryType = '__NONE__';
        }
      } else {
        const typeValues = typeStr.split(',');
        if (typeValues.length > 1) {
          where.primaryType = { in: typeValues };
        } else {
          where.primaryType = typeValues[0];
        }
      }
    }

    if (repository) {
      where.repository = {
        contains: repository as string
      };
    }

    if (domain) {
      // Merge with the tenant scope rather than replacing it
      where.scan = {
        ...where.scan,
        domain: { ...(where.scan?.domain ?? {}), name: domain as string }
      };
    }

    if (verified !== undefined) {
      where.verified = verified === 'true';
    }

    if (falsePositive !== undefined) {
      where.falsePositive = falsePositive === 'true';
    }

    if (search) {
      where.OR = [
        { repository: { contains: search as string } },
        { filePath: { contains: search as string } },
        {
          secrets: {
            some: {
              OR: [
                { content: { contains: search as string } },
                { context: { contains: search as string } }
              ]
            }
          }
        }
      ];
    }

    if (scanId) {
      where.scanId = scanId as string;
    }

    const skip = (Number(page) - 1) * Number(limit);

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        include: {
          scan: {
            include: {
              domain: {
                include: {
                  organization: { select: { id: true, name: true, slug: true } }
                }
              }
            }
          },
          secrets: true
        },
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
    logger.error('Error fetching findings:', error);
    res.status(500).json({ error: 'Failed to fetch findings' });
  }
}

/**
 * Get finding by ID
 * GET /api/findings/:id
 */
export async function getFinding(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scope = scopeFor(req);
    const finding = await prisma.finding.findFirst({
      where: { id, ...scope.finding },
      include: {
        scan: {
          include: {
            domain: {
              include: {
                organization: { select: { id: true, name: true, slug: true } }
              }
            }
          }
        },
        secrets: true
      }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    res.json(finding);
  } catch (error: any) {
    logger.error('Error fetching finding:', error);
    res.status(500).json({ error: 'Failed to fetch finding' });
  }
}

/**
 * Update finding
 * PUT /api/findings/:id
 */
export async function updateFinding(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;
    const { verified, falsePositive, acknowledged, notes } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scope = scopeFor(req);
    const finding = await prisma.finding.findFirst({
      where: { id, ...scope.finding },
      include: { scan: true }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    const updated = await prisma.finding.update({
      where: { id },
      data: {
        ...(verified !== undefined && { verified }),
        ...(falsePositive !== undefined && { falsePositive }),
        ...(acknowledged !== undefined && { acknowledged }),
        ...(notes !== undefined && { notes })
      }
    });

    logger.info(`Finding updated: ${id}`);

    res.json(updated);
  } catch (error: any) {
    logger.error('Error updating finding:', error);
    res.status(500).json({ error: 'Failed to update finding' });
  }
}

/**
 * Bulk update findings
 * POST /api/findings/bulk-update
 */
export async function bulkUpdateFindings(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { findingIds, updates } = req.body;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!findingIds || !Array.isArray(findingIds) || findingIds.length === 0) {
      return res.status(400).json({ error: 'Finding IDs array is required' });
    }

    // Every id must be inside the requester's scope
    const scope = scopeFor(req);
    const findings = await prisma.finding.findMany({
      where: { id: { in: findingIds }, ...scope.finding },
      select: { id: true }
    });

    if (findings.length !== findingIds.length) {
      return res.status(403).json({ error: 'Access denied or findings not found' });
    }

    // Restrict the write to the ids we just authorised, and to the fields a
    // client is allowed to change.
    const allowed: any = {};
    if (typeof updates?.verified === 'boolean') allowed.verified = updates.verified;
    if (typeof updates?.falsePositive === 'boolean') allowed.falsePositive = updates.falsePositive;
    if (typeof updates?.acknowledged === 'boolean') allowed.acknowledged = updates.acknowledged;
    if (typeof updates?.notes === 'string') allowed.notes = updates.notes;

    if (Object.keys(allowed).length === 0) {
      return res.status(400).json({ error: 'No updatable fields provided' });
    }

    const result = await prisma.finding.updateMany({
      where: { id: { in: findings.map(f => f.id) } },
      data: allowed
    });

    logger.info(`Bulk updated ${result.count} findings`);

    res.json({ updated: result.count });
  } catch (error: any) {
    logger.error('Error bulk updating findings:', error);
    res.status(500).json({ error: 'Failed to bulk update findings' });
  }
}

/**
 * Delete finding
 * DELETE /api/findings/:id
 */
export async function deleteFinding(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scope = scopeFor(req);
    const finding = await prisma.finding.findFirst({
      where: { id, ...scope.finding },
      include: { scan: true }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    await prisma.finding.delete({
      where: { id }
    });

    logger.info(`Finding deleted: ${id}`);

    res.json({ message: 'Finding deleted successfully' });
  } catch (error: any) {
    logger.error('Error deleting finding:', error);
    res.status(500).json({ error: 'Failed to delete finding' });
  }
}

/**
 * Export findings as CSV
 * GET /api/findings/export
 *
 * Gated by the finding:export permission, which an organization can withdraw
 * from all of its members via its canExport toggle.
 */
export async function exportFindings(req: Request, res: Response) {
  try {
    const { domain, criticality } = req.query;
    const scope = scopeFor(req);

    const where: any = { ...scope.finding };
    if (criticality) where.criticality = criticality as string;
    if (domain) {
      where.scan = { ...(where.scan ?? {}), domain: { ...(where.scan?.domain ?? {}), name: domain as string } };
    }

    const findings = await prisma.finding.findMany({
      where,
      include: {
        scan: {
          include: {
            domain: {
              include: {
                organization: { select: { id: true, name: true, slug: true } }
              }
            }
          }
        },
        secrets: true
      },
      orderBy: { score: 'desc' },
      take: 10000,
    });

    const escape = (value: any) => {
      const text = value === null || value === undefined ? '' : String(value);
      return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
    };

    const header = [
      'organization', 'domain', 'criticality', 'score', 'primaryType', 'repository', 'filePath',
      'fileUrl', 'commitDate', 'verified', 'falsePositive', 'acknowledged', 'secretCount', 'secretTypes',
    ];

    const rows = findings.map(f => [
      f.scan?.domain?.organization?.name, f.scan?.domain?.name, f.criticality, f.score, f.primaryType, f.repository, f.filePath,
      f.fileUrl, f.commitDate?.toISOString() ?? '', f.verified, f.falsePositive, f.acknowledged,
      f.secrets.length, Array.from(new Set(f.secrets.map(s => s.type))).join(' '),
    ].map(escape).join(','));

    const csv = [header.join(','), ...rows].join('\n');

    logger.info(`Findings exported by ${req.user?.email}: ${findings.length} row(s)`);

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="findings-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(csv);
  } catch (error: any) {
    logger.error('Error exporting findings:', error);
    res.status(500).json({ error: 'Failed to export findings' });
  }
}

/**
 * Get findings statistics
 * GET /api/findings/stats
 * Optimized: uses groupBy instead of 8 separate COUNT queries
 */
export async function getStatistics(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    const { domain } = req.query;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const scope = scopeFor(req);
    const baseWhere: any = { ...scope.finding };
    if (domain) {
      baseWhere.scan = { ...(baseWhere.scan ?? {}), domain: { ...(baseWhere.scan?.domain ?? {}), name: domain as string } };
    }

    // Cross-org breakdown for a super admin viewing every organization at
    // once. Finding has no direct orgId (org is reached via scan -> domain),
    // so groupBy can't express this — a raw join is the only way to get counts
    // per organization without N+1 queries.
    const wantsOrgBreakdown = scope.unscoped && !domain;

    // Optimized: single groupBy for criticality counts instead of 8 separate COUNT queries
    const [
      criticalityGroups,
      verifiedCount,
      falsePositiveCount,
      byType,
      topRepositories,
      topFiles,
      uniqueEmailGroups,
      uniqueRepositoriesGroups,
      uniqueFilesGroups,
      orgBreakdownRows
    ] = await Promise.all([
      prisma.finding.groupBy({
        by: ['criticality'],
        where: baseWhere,
        _count: true
      }),
      prisma.finding.count({ where: { ...baseWhere, verified: true } }),
      prisma.finding.count({ where: { ...baseWhere, falsePositive: true } }),
      prisma.finding.groupBy({
        by: ['primaryType'],
        where: baseWhere,
        _count: true
      }),
      prisma.finding.groupBy({
        by: ['repository'],
        where: baseWhere,
        _count: true,
        orderBy: { _count: { repository: 'desc' } },
        take: 10
      }),
      // Get top files by the number of findings they appear in (high-performance SQLite group-by)
      prisma.finding.groupBy({
        by: ['filePath'],
        where: baseWhere,
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        },
        take: 10
      }),
      // Count unique email addresses (grouped by content where type = EMAIL)
      prisma.secret.groupBy({
        by: ['content'],
        where: { type: 'EMAIL', finding: baseWhere }
      }),
      // Total unique repositories
      prisma.finding.groupBy({
        by: ['repository'],
        where: baseWhere
      }),
      // Total unique files
      prisma.finding.groupBy({
        by: ['filePath'],
        where: baseWhere
      }),
      // Per-organization totals, only computed for the unscoped all-orgs view
      wantsOrgBreakdown
        ? prisma.$queryRaw<Array<{ orgId: string; orgName: string; orgSlug: string; total: number; critical: number; high: number }>>`
            SELECT o.id as orgId, o.name as orgName, o.slug as orgSlug,
              COUNT(f.id) as total,
              SUM(CASE WHEN f.criticality = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
              SUM(CASE WHEN f.criticality = 'HIGH' THEN 1 ELSE 0 END) as high
            FROM "Organization" o
            JOIN "Domain" d ON d."orgId" = o.id
            JOIN "Scan" s ON s."domainId" = d.id
            JOIN "Finding" f ON f."scanId" = s.id
            GROUP BY o.id, o.name, o.slug
            ORDER BY total DESC
          `
        : Promise.resolve([])
    ]);

    // Build criticality map from groupBy result
    const critMap: Record<string, number> = {};
    let totalFindings = 0;
    for (const group of criticalityGroups) {
      critMap[group.criticality] = group._count;
      totalFindings += group._count;
    }

    res.json({
      overview: {
        total: totalFindings,
        byCriticality: {
          critical: critMap['CRITICAL'] || 0,
          high: critMap['HIGH'] || 0,
          medium: critMap['MEDIUM'] || 0,
          low: critMap['LOW'] || 0,
          info: critMap['INFO'] || 0
        },
        verified: verifiedCount,
        falsePositives: falsePositiveCount
      },
      byType: byType.map((item: any) => ({
        type: item.primaryType,
        count: item._count
      })),
      topRepositories: topRepositories.map((item: any) => ({
        repository: item.repository,
        count: item._count
      })),
      topFiles: topFiles.map((item: any) => ({
        filePath: item.filePath,
        count: item._count.id
      })),
      uniqueEmails: uniqueEmailGroups.length,
      uniqueFindingTypes: byType.length,
      uniqueRepositories: uniqueRepositoriesGroups.length,
      uniqueFiles: uniqueFilesGroups.length,
      byOrganization: (orgBreakdownRows as any[]).map((row) => ({
        orgId: row.orgId,
        orgName: row.orgName,
        orgSlug: row.orgSlug,
        total: Number(row.total),
        critical: Number(row.critical),
        high: Number(row.high),
      }))
    });
  } catch (error: any) {
    logger.error('Error fetching statistics:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
}
