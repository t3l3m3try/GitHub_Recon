import { Request, Response } from 'express';
import {
  SECRET_PATTERNS,
  FALSE_POSITIVE_PATTERNS,
  FALSE_POSITIVE_CONTEXT_SUBSTRINGS,
} from '../utils/patterns';
import {
  TYPE_WEIGHTS,
  DEFAULT_TYPE_WEIGHT,
  MAX_TYPE_SCORE,
  MAX_ENTROPY_SCORE,
  MAX_CONTEXT_SCORE,
  MAX_RECENCY_SCORE,
  MAX_CRITICALITY_SCORE,
  ENTROPY_SATURATION_VALUE,
  CRITICAL_CONTEXT_KEYWORDS,
  HIGH_RISK_CONTEXT_KEYWORDS,
  CRITICAL_KEYWORD_BONUS,
  HIGH_RISK_KEYWORD_BONUS,
  COMMENT_CONTEXT_PENALTY,
  ENV_VAR_CONTEXT_BONUS,
  RECENCY_BRACKETS,
  RECENCY_DEFAULT_SCORE,
  CRITICALITY_THRESHOLDS,
  FILE_DENSITY_BONUS_PER_TYPE,
  FILE_DENSITY_HIGH_VALUE_THRESHOLD,
} from '../services/scoring.service';
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
 * Get every secret-detection pattern, grouped by type, plus the global
 * settings that shape what actually becomes a finding: per-type severity
 * weight, false-positive suppression rules, the always-on per-domain email
 * pattern, and the full criticality scoring model.
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
        // Base contribution to the 0-100 criticality score every match of this
        // type receives — see scoring.service.ts calculateCriticalityScore().
        severityWeight: TYPE_WEIGHTS[type] ?? DEFAULT_TYPE_WEIGHT,
        isDefaultWeight: !(type in TYPE_WEIGHTS),
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
      falsePositiveFilters: {
        // Any match whose own text matches one of these is discarded, regardless of type.
        contentPatterns: FALSE_POSITIVE_PATTERNS.map(p => ({ source: p.source, flags: p.flags })),
        // Any match whose surrounding context contains one of these substrings is discarded.
        contextSubstrings: FALSE_POSITIVE_CONTEXT_SUBSTRINGS,
      },
      // Every scan additionally matches any email address at the scanned domain,
      // independent of the static patterns above — see getDomainPatterns() in utils/patterns.ts.
      domainPattern: {
        type: 'EMAIL',
        description: 'Email addresses at the scanned domain',
        template: '[a-zA-Z0-9._%+-]+@{domain}',
        entropyThreshold: 0,
        contextKeywords: ['email', 'mail', 'contact'],
      },
      // The full 0-100 criticality formula — see scoring.service.ts calculateCriticalityScore()
      // and calculateFileCriticalityScore(). Kept here as one source of truth so the UI never
      // hardcodes numbers that could drift from the actual scoring logic.
      criticalityModel: {
        maxScore: MAX_CRITICALITY_SCORE,
        components: [
          {
            key: 'type',
            label: 'Secret type',
            maxPoints: MAX_TYPE_SCORE,
            description: 'Fixed weight per secret type, set by how sensitive that type of credential typically is. Unweighted types default to ' + DEFAULT_TYPE_WEIGHT + '.',
          },
          {
            key: 'entropy',
            label: 'Entropy',
            maxPoints: MAX_ENTROPY_SCORE,
            description: `Shannon entropy of the matched text, scaled linearly: entropy ${ENTROPY_SATURATION_VALUE} or higher saturates the full ${MAX_ENTROPY_SCORE} points.`,
          },
          {
            key: 'context',
            label: 'Surrounding context',
            maxPoints: MAX_CONTEXT_SCORE,
            description: 'Keyword and code-shape signals in the text around the match — see contextRules below.',
          },
          {
            key: 'recency',
            label: 'Commit recency',
            maxPoints: MAX_RECENCY_SCORE,
            description: 'How recently the match was committed — see recencyBrackets below.',
          },
        ],
        contextRules: {
          criticalKeywords: CRITICAL_CONTEXT_KEYWORDS,
          criticalKeywordBonus: CRITICAL_KEYWORD_BONUS,
          highRiskKeywords: HIGH_RISK_CONTEXT_KEYWORDS,
          highRiskKeywordBonus: HIGH_RISK_KEYWORD_BONUS,
          commentPenalty: COMMENT_CONTEXT_PENALTY,
          envVarBonus: ENV_VAR_CONTEXT_BONUS,
        },
        recencyBrackets: RECENCY_BRACKETS,
        recencyDefaultScore: RECENCY_DEFAULT_SCORE,
        criticalityThresholds: CRITICALITY_THRESHOLDS,
        fileAggregation: {
          description: 'A file with several secrets takes the highest individual score, plus a density bonus for each additional distinct high-value type.',
          highValueThreshold: FILE_DENSITY_HIGH_VALUE_THRESHOLD,
          bonusPerAdditionalType: FILE_DENSITY_BONUS_PER_TYPE,
        },
      },
    });
  } catch (error: any) {
    logger.error('Error fetching patterns:', error);
    res.status(500).json({ error: 'Failed to fetch patterns' });
  }
}
