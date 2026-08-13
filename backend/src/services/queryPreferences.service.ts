import prisma from '../config/database';
import {
  ALL_QUERY_IDS,
  QueryTarget,
  getAreasForTarget,
  isKnownQueryId,
  renderQuery,
} from '../utils/queryCatalog';
import { logger } from '../utils/logger';

/**
 * Query Preferences Service
 *
 * Resolves which catalog queries a user has enabled. Storage is sparse — only
 * explicit toggles land in QuerySetting, and a missing row means ENABLED. That
 * keeps newly shipped catalog queries live by default instead of silently off.
 */

export interface ResolvedQuery {
  id: string;
  label: string;
  /** Fully rendered GitHub search string, domain substituted. */
  query: string;
}

export interface QueryStateUpdate {
  queryId: string;
  enabled: boolean;
}

/**
 * Map of queryId → enabled for every catalog query (defaults filled in).
 */
export async function getQueryStates(userId: string): Promise<Map<string, boolean>> {
  const rows = await prisma.querySetting.findMany({
    where: { userId },
    select: { queryId: true, enabled: true },
  });

  const overrides = new Map(rows.map(row => [row.queryId, row.enabled]));
  const states = new Map<string, boolean>();
  for (const id of ALL_QUERY_IDS) {
    states.set(id, overrides.get(id) ?? true);
  }
  return states;
}

/**
 * The set of query IDs that should run — every catalog query except those
 * explicitly disabled.
 */
export async function getEnabledQueryIds(userId: string): Promise<Set<string>> {
  const disabled = await prisma.querySetting.findMany({
    where: { userId, enabled: false },
    select: { queryId: true },
  });

  const disabledIds = new Set(disabled.map(row => row.queryId));
  return new Set(ALL_QUERY_IDS.filter(id => !disabledIds.has(id)));
}

/**
 * Persist toggles. Unknown query IDs are rejected so a stale client cannot
 * write orphan rows.
 */
export async function setQueryStates(userId: string, updates: QueryStateUpdate[]): Promise<void> {
  const unknown = updates.filter(update => !isKnownQueryId(update.queryId)).map(u => u.queryId);
  if (unknown.length > 0) {
    throw new Error(`Unknown query id(s): ${unknown.slice(0, 5).join(', ')}`);
  }

  for (const { queryId, enabled } of updates) {
    await prisma.querySetting.upsert({
      where: { userId_queryId: { userId, queryId } },
      update: { enabled },
      create: { userId, queryId, enabled },
    });
  }

  logger.info(`Query preferences updated for ${userId}: ${updates.length} change(s)`);
}

/**
 * Drop every override, returning the user to the all-enabled default.
 */
export async function resetToDefaults(userId: string): Promise<void> {
  const { count } = await prisma.querySetting.deleteMany({ where: { userId } });
  logger.info(`Query preferences reset for ${userId}: ${count} override(s) removed`);
}

/**
 * The enabled queries for one target, rendered against the scanned domain and
 * kept in catalog order.
 */
export function resolveQueriesForTarget(
  target: QueryTarget,
  enabledIds: Set<string>,
  domain: string
): ResolvedQuery[] {
  const resolved: ResolvedQuery[] = [];
  for (const area of getAreasForTarget(target)) {
    for (const query of area.queries) {
      if (!enabledIds.has(query.id)) continue;
      resolved.push({
        id: query.id,
        label: query.label,
        query: renderQuery(query.template, domain),
      });
    }
  }
  return resolved;
}
