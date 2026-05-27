import { Request, Response } from 'express';
import prisma from '../config/database';
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

    const where: any = {
      scan: {
        userId
      }
    };

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
      where.scan = {
        ...where.scan,
        domain: {
          name: domain as string
        }
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
              domain: true
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

    const finding = await prisma.finding.findUnique({
      where: { id },
      include: {
        scan: {
          include: {
            domain: true
          }
        },
        secrets: true
      }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    if (finding.scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
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

    const finding = await prisma.finding.findUnique({
      where: { id },
      include: { scan: true }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    if (finding.scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
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

    // Verify all findings belong to user
    const findings = await prisma.finding.findMany({
      where: {
        id: { in: findingIds },
        scan: { userId }
      }
    });

    if (findings.length !== findingIds.length) {
      return res.status(403).json({ error: 'Access denied or findings not found' });
    }

    // Perform bulk update
    const result = await prisma.finding.updateMany({
      where: {
        id: { in: findingIds }
      },
      data: updates
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

    const finding = await prisma.finding.findUnique({
      where: { id },
      include: { scan: true }
    });

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    if (finding.scan.userId !== userId) {
      return res.status(403).json({ error: 'Access denied' });
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

    const baseWhere: any = { scan: { userId } };
    if (domain) {
      baseWhere.scan = { ...baseWhere.scan, domain: { name: domain as string } };
    }

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
      uniqueFilesGroups
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
      })
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
      uniqueFiles: uniqueFilesGroups.length
    });
  } catch (error: any) {
    logger.error('Error fetching statistics:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
}
