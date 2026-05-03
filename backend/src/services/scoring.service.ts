import { calculateEntropy, hasContextKeywords } from '../utils/patterns';

/**
 * Scoring Service
 * Calculates criticality score for findings based on multiple factors
 */

interface ScoringContext {
  type: string;
  content: string;
  context: string;
  repository?: string;
  commitDate?: Date;
  entropy?: number;
}

// Type weights (out of 40 points)
const TYPE_WEIGHTS: Record<string, number> = {
  AWS_SECRET_KEY: 40,
  PRIVATE_KEY: 40,
  CREDENTIAL_PAIR: 38, // email + password combination — always HIGH
  DATABASE_URL: 38,
  AWS_ACCESS_KEY: 36,
  STRIPE_KEY: 35,
  GITHUB_TOKEN: 32,
  SLACK_TOKEN: 30,
  GOOGLE_API_KEY: 28,
  AZURE_KEY: 28,
  SENDGRID_KEY: 26,
  TWILIO_KEY: 26,
  MAILCHIMP_KEY: 24,
  DATADOG_KEY: 24,
  NPM_TOKEN: 22,
  NPMRC_AUTH: 22,
  JWT_SECRET: 20,
  API_KEY: 18,
  DOCKER_PASSWORD: 16,
  PASSWORD: 14,
  GENERIC_SECRET: 12,
  EMAIL: 6,
  DOMAIN: 4
};

// High-risk context keywords
const CRITICAL_CONTEXT_KEYWORDS = [
  'prod', 'production', 'live', 'master', 'main',
  'api', 'secret', 'private', 'credential', 'auth'
];

const HIGH_RISK_CONTEXT_KEYWORDS = [
  'staging', 'dev', 'development', 'test', 'beta',
  'key', 'token', 'password', 'config'
];

/**
 * Calculate criticality score (0-100)
 */
export function calculateCriticalityScore(context: ScoringContext): number {
  let score = 0;

  // 1. Type-based score (40 points max)
  score += TYPE_WEIGHTS[context.type] || 10;

  // 2. Entropy score (25 points max)
  const entropy = context.entropy || calculateEntropy(context.content);
  const entropyScore = Math.min(25, (entropy / 5) * 25);
  score += entropyScore;

  // 3. Context analysis (30 points max)
  const contextScore = analyzeContext(context.context);
  score += contextScore;

  // 4. Recency (5 points max)
  const recencyScore = analyzeRecency(context.commitDate);
  score += recencyScore;

  // Ensure score is between 0-100
  return Math.min(100, Math.max(0, score));
}

/**
 * Analyze context for risk indicators (0-30 points)
 */
function analyzeContext(context: string): number {
  if (!context) return 0;

  const lowerContext = context.toLowerCase();
  let score = 0;

  // Critical keywords (+20 points)
  const hasCriticalKeywords = CRITICAL_CONTEXT_KEYWORDS.some(
    keyword => lowerContext.includes(keyword)
  );
  if (hasCriticalKeywords) score += 20;

  // High-risk keywords (+12 points)
  const hasHighRiskKeywords = HIGH_RISK_CONTEXT_KEYWORDS.some(
    keyword => lowerContext.includes(keyword)
  );
  if (hasHighRiskKeywords) score += 12;

  // Comments or documentation context (lower score by 5)
  if (lowerContext.includes('//') || lowerContext.includes('/*') ||
    lowerContext.includes('#') || lowerContext.includes('"""')) {
    score -= 5;
  }

  // Environment variable pattern (+10 points)
  if (/export\s+\w+=/i.test(context) || /\w+\s*=\s*process\.env/i.test(context)) {
    score += 10;
  }

  return Math.min(30, Math.max(0, score));
}

/**
 * Analyze commit recency (0-5 points)
 */
function analyzeRecency(commitDate?: Date): number {
  if (!commitDate) return 3; // Default score

  const now = new Date();
  const daysDiff = (now.getTime() - commitDate.getTime()) / (1000 * 60 * 60 * 24);

  if (daysDiff < 7) return 5;      // Last week
  if (daysDiff < 30) return 4;     // Last month
  if (daysDiff < 90) return 3;     // Last quarter
  if (daysDiff < 365) return 2;    // Last year
  return 1;                         // Older
}

/**
 * Convert score to criticality level
 */
export function scoreToCriticality(score: number): string {
  if (score >= 90) return 'CRITICAL';
  if (score >= 75) return 'HIGH';
  if (score >= 50) return 'MEDIUM';
  if (score >= 25) return 'LOW';
  return 'INFO';
}

/**
 * Calculate the aggregate criticality score for a file based on its constituent secrets
 * 1. Base Score = Maximum individual secret score
 * 2. Density Bonus = +2 per additional critical/high secret type found in the file
 */
export function calculateFileCriticalityScore(secrets: { type: string; score: number }[]): { score: number; primaryType: string; criticality: string } {
  if (!secrets || secrets.length === 0) {
    return { score: 0, primaryType: 'UNKNOWN', criticality: 'INFO' };
  }

  // Find the secret with the highest score
  let maxScore = -1;
  let primaryType = 'UNKNOWN';

  for (const s of secrets) {
    if (s.score > maxScore) {
      maxScore = s.score;
      primaryType = s.type;
    }
  }

  // Calculate density bonus based on variety of high-value secrets (e.g. ones with >= 75 criticalities)
  let bonus = 0;
  const highValueTypesFound = new Set<string>();

  for (const s of secrets) {
    // Treat any secret that scores >= 75 as high value
    if (s.score >= 75) {
      highValueTypesFound.add(s.type);
    }
  }

  // If there's more than 1 unique high-value type, give +2 for each additional type
  if (highValueTypesFound.size > 1) {
    bonus = (highValueTypesFound.size - 1) * 2;
  }

  // Calculate final score
  const finalScore = Math.min(100, Math.max(0, maxScore + bonus));
  const criticality = scoreToCriticality(finalScore);

  return { score: finalScore, primaryType, criticality };
}

