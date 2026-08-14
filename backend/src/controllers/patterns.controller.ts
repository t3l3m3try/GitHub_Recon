import { Request, Response } from 'express';
import { SECRET_PATTERNS } from '../utils/patterns';
import { logger } from '../utils/logger';

/**
 * Patterns Controller
 *
 * Read-only view of the regex patterns the scanner uses to extract secrets
 * from GitHub search results — a separate stage from the search queries
 * themselves (see queries.controller.ts / utils/queryCatalog.ts). These are
 * not user-configurable, so unlike queries there is nothing to toggle here.
 */

/**
 * Get every secret-detection pattern, grouped by type.
 * GET /api/patterns
 */
export async function getPatterns(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const grouped = new Map<string, typeof SECRET_PATTERNS>();
    for (const p of SECRET_PATTERNS) {
      if (!grouped.has(p.type)) grouped.set(p.type, []);
      grouped.get(p.type)!.push(p);
    }

    const groups = Array.from(grouped.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([type, patterns]) => ({
        type,
        count: patterns.length,
        patterns: patterns.map(p => ({
          description: p.description,
          source: p.pattern.source,
          flags: p.pattern.flags,
          entropyThreshold: p.entropyThreshold ?? null,
          contextKeywords: p.contextKeywords ?? [],
          exampleMatch: p.exampleMatch ?? null,
        })),
      }));

    res.json({
      groups,
      total: SECRET_PATTERNS.length,
    });
  } catch (error: any) {
    logger.error('Error fetching patterns:', error);
    res.status(500).json({ error: 'Failed to fetch patterns' });
  }
}
