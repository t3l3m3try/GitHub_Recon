import { Request, Response } from 'express';
import {
  QUERY_CATALOG,
  QueryTarget,
  TARGET_DESCRIPTIONS,
  TARGET_LABELS,
  renderQuery,
} from '../utils/queryCatalog';
import {
  getQueryStates,
  resetToDefaults,
  setQueryStates,
} from '../services/queryPreferences.service';
import { logger } from '../utils/logger';

/**
 * Queries Controller
 * Exposes the query catalog plus the user's enable/disable selection.
 */

const TARGET_ORDER: QueryTarget[] = ['code', 'commits', 'issues'];

/**
 * Build the catalog payload annotated with the user's selection.
 * `domain` is optional — when supplied each query carries a rendered preview,
 * otherwise the raw {domain} template is shown.
 */
async function buildCatalogPayload(userId: string, domain?: string) {
  const states = await getQueryStates(userId);

  const targets = TARGET_ORDER.map(target => {
    const areas = QUERY_CATALOG
      .filter(area => area.target === target)
      .map(area => {
        const queries = area.queries.map(query => ({
          id: query.id,
          label: query.label,
          template: query.template,
          preview: domain ? renderQuery(query.template, domain) : query.template,
          enabled: states.get(query.id) ?? true,
        }));

        return {
          id: area.id,
          name: area.name,
          description: area.description,
          total: queries.length,
          enabledCount: queries.filter(q => q.enabled).length,
          queries,
        };
      });

    const total = areas.reduce((sum, area) => sum + area.total, 0);
    const enabledCount = areas.reduce((sum, area) => sum + area.enabledCount, 0);

    return {
      id: target,
      name: TARGET_LABELS[target],
      description: TARGET_DESCRIPTIONS[target],
      total,
      enabledCount,
      areas,
    };
  });

  return {
    targets,
    totals: {
      total: targets.reduce((sum, t) => sum + t.total, 0),
      enabled: targets.reduce((sum, t) => sum + t.enabledCount, 0),
    },
  };
}

/**
 * Get the full query catalog with the user's selection
 * GET /api/queries?domain=example.com
 */
export async function getQueries(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const domain = typeof req.query.domain === 'string' && req.query.domain.trim()
      ? req.query.domain.trim()
      : undefined;

    res.json(await buildCatalogPayload(userId, domain));
  } catch (error: any) {
    logger.error('Error fetching queries:', error);
    res.status(500).json({ error: 'Failed to fetch queries' });
  }
}

/**
 * Bulk enable/disable queries
 * PUT /api/queries
 */
export async function updateQueries(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { updates } = req.body;

    if (!Array.isArray(updates)) {
      return res.status(400).json({ error: 'updates must be an array of { queryId, enabled }' });
    }

    const malformed = updates.some(
      (u: any) => !u || typeof u.queryId !== 'string' || typeof u.enabled !== 'boolean'
    );
    if (malformed) {
      return res.status(400).json({ error: 'Each update must be { queryId: string, enabled: boolean }' });
    }

    await setQueryStates(userId, updates);

    const domain = typeof req.query.domain === 'string' && req.query.domain.trim()
      ? req.query.domain.trim()
      : undefined;

    res.json(await buildCatalogPayload(userId, domain));
  } catch (error: any) {
    if (error.message?.startsWith('Unknown query id')) {
      return res.status(400).json({ error: error.message });
    }
    logger.error('Error updating queries:', error);
    res.status(500).json({ error: 'Failed to update queries' });
  }
}

/**
 * Restore the all-enabled default
 * POST /api/queries/reset
 */
export async function resetQueries(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    await resetToDefaults(userId);

    const domain = typeof req.query.domain === 'string' && req.query.domain.trim()
      ? req.query.domain.trim()
      : undefined;

    res.json(await buildCatalogPayload(userId, domain));
  } catch (error: any) {
    logger.error('Error resetting queries:', error);
    res.status(500).json({ error: 'Failed to reset queries' });
  }
}
