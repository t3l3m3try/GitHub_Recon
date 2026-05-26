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
  'AWS_SECRET_KEY': 40,
  'PRIVATE_KEY': 40,
  'CREDENTIAL_PAIR': 38, // email + password combination — always HIGH
  'DATABASE_URL': 38,
  'CONNECTION_STRING': 38,
  'AWS_ACCESS_KEY': 36,
  'STRIPE_KEY': 35,
  'SQUARE_KEY': 34,
  'PAYPAL_TOKEN': 34,
  'GITHUB_TOKEN': 32,
  'GITLAB_TOKEN': 32,
  'BITBUCKET_TOKEN': 30,
  'SLACK_TOKEN': 30,
  'HEROKU_KEY': 30,
  'CLOUDFLARE_KEY': 30,
  'SHOPIFY_KEY': 28,
  'GOOGLE_API_KEY': 28,
  'AZURE_KEY': 28,
  'SSH_KEY': 28,
  'PGP_KEY': 28,
  'SENDGRID_KEY': 26,
  'TWILIO_KEY': 26,
  'MAILCHIMP_KEY': 24,
  'DATADOG_KEY': 24,
  'SLACK_WEBHOOK': 22,
  'NPM_TOKEN': 22,
  'NPMRC_AUTH': 22,
  'OAUTH_TOKEN': 22,
  'BEARER_TOKEN': 20,
  'JWT_SECRET': 20,
  'FIREBASE_KEY': 20,
  'API_KEY': 18,
  'DOCKER_PASSWORD': 16,
  'PASSWORD': 14,
  'GENERIC_SECRET': 12,
  'EMAIL': 6,
  'DOMAIN': 4,
  // --- BETTERLEAKS PRECISION WEIGHTS ---
  '1PASSWORD_SECRET_KEY': 40,
  '1PASSWORD_SERVICE_ACCOUNT_TOKEN': 40,
  'ADAFRUIT_API_KEY': 35,
  'ADOBE_CLIENT_ID': 15,
  'ADOBE_CLIENT_SECRET': 40,
  'AGE_SECRET_KEY': 40,
  'AIRTABLE_API_KEY': 35,
  'AIRTABLE_PERSONNAL_ACCESS_TOKEN': 35,
  'ALGOLIA_API_KEY': 35,
  'ALIBABA_ACCESS_KEY_ID': 15,
  'ALIBABA_SECRET_KEY': 40,
  'ANTHROPIC_ADMIN_API_KEY': 35,
  'ANTHROPIC_API_KEY': 35,
  'ARTIFACTORY_API_KEY': 35,
  'ARTIFACTORY_REFERENCE_TOKEN': 35,
  'ASANA_CLIENT_ID': 15,
  'ASANA_CLIENT_SECRET': 40,
  'ASSEMBLYAI_API_KEY': 35,
  'ATLASSIAN_API_TOKEN': 35,
  'AUTHRESS_SERVICE_CLIENT_ACCESS_KEY': 35,
  'AWS_ACCESS_TOKEN': 35,
  'AWS_AMAZON_BEDROCK_API_KEY_LONG_LIVED': 35,
  'AWS_AMAZON_BEDROCK_API_KEY_SHORT_LIVED': 35,
  'AWS_SECRET_ACCESS_KEY': 40,
  'AZURE_AD_CLIENT_SECRET': 40,
  'BEAMER_API_TOKEN': 35,
  'BITBUCKET_CLIENT_ID': 15,
  'BITBUCKET_CLIENT_SECRET': 40,
  'BITTREX_ACCESS_KEY': 35,
  'BITTREX_SECRET_KEY': 40,
  'CEREBRAS_API_KEY': 35,
  'CISCO_MERAKI_API_KEY': 35,
  'CLICKHOUSE_CLOUD_API_SECRET_KEY': 40,
  'CLOJARS_API_TOKEN': 35,
  'CLOUDFLARE_API_KEY': 35,
  'CLOUDFLARE_GLOBAL_API_KEY': 35,
  'CLOUDFLARE_ORIGIN_CA_KEY': 25,
  'CODECOV_ACCESS_TOKEN': 35,
  'COHERE_API_TOKEN': 35,
  'COINBASE_ACCESS_TOKEN': 35,
  'CONFLUENT_ACCESS_TOKEN': 35,
  'CONFLUENT_SECRET_KEY': 40,
  'CONTENTFUL_DELIVERY_API_TOKEN': 35,
  'CURL_AUTH_HEADER': 25,
  'CURL_AUTH_USER': 25,
  'CURSOR_API_KEY': 35,
  'DATABRICKS_API_TOKEN': 35,
  'DATADOG_ACCESS_TOKEN': 35,
  'DEEPGRAM_API_KEY': 35,
  'DEEPSEEK_API_KEY': 35,
  'DEFINED_NETWORKING_API_TOKEN': 35,
  'DIGITALOCEAN_ACCESS_TOKEN': 35,
  'DIGITALOCEAN_PAT': 35,
  'DIGITALOCEAN_REFRESH_TOKEN': 35,
  'DISCORD_API_TOKEN': 35,
  'DISCORD_CLIENT_ID': 15,
  'DISCORD_CLIENT_SECRET': 40,
  'DOPPLER_API_TOKEN': 35,
  'DRONECI_ACCESS_TOKEN': 35,
  'DROPBOX_API_TOKEN': 35,
  'DROPBOX_LONG_LIVED_API_TOKEN': 35,
  'DROPBOX_SHORT_LIVED_API_TOKEN': 35,
  'DUFFEL_API_TOKEN': 35,
  'DYNATRACE_API_TOKEN': 35,
  'EASYPOST_API_TOKEN': 35,
  'EASYPOST_TEST_API_TOKEN': 35,
  'ELEVENLABS_API_KEY': 35,
  'ENDORLABS_API_KEY': 35,
  'ENDORLABS_API_SECRET': 40,
  'ETSY_ACCESS_TOKEN': 35,
  'FACEBOOK_ACCESS_TOKEN': 35,
  'FACEBOOK_PAGE_ACCESS_TOKEN': 35,
  'FACEBOOK_SECRET': 40,
  'FASTLY_API_TOKEN': 35,
  'FINICITY_API_TOKEN': 35,
  'FINICITY_CLIENT_SECRET': 40,
  'FINNHUB_ACCESS_TOKEN': 35,
  'FLICKR_ACCESS_TOKEN': 35,
  'FLUTTERWAVE_ENCRYPTION_KEY': 25,
  'FLUTTERWAVE_PUBLIC_KEY': 15,
  'FLUTTERWAVE_SECRET_KEY': 40,
  'FLYIO_ACCESS_TOKEN': 35,
  'FRAMEIO_API_TOKEN': 35,
  'FREEMIUS_SECRET_KEY': 40,
  'FRESHBOOKS_ACCESS_TOKEN': 35,
  'GCP_API_KEY': 35,
  'GITEA_ACCESS_TOKEN': 35,
  'GITHUB_APP_TOKEN': 35,
  'GITHUB_FINE_GRAINED_PAT': 35,
  'GITHUB_OAUTH': 25,
  'GITHUB_PAT': 35,
  'GITHUB_REFRESH_TOKEN': 35,
  'GITLAB_CICD_JOB_TOKEN': 35,
  'GITLAB_DEPLOY_TOKEN': 35,
  'GITLAB_FEATURE_FLAG_CLIENT_TOKEN': 35,
  'GITLAB_FEED_TOKEN': 35,
  'GITLAB_INCOMING_MAIL_TOKEN': 35,
  'GITLAB_KUBERNETES_AGENT_TOKEN': 35,
  'GITLAB_OAUTH_APP_SECRET': 40,
  'GITLAB_PAT': 35,
  'GITLAB_PAT_ROUTABLE': 35,
  'GITLAB_PTT': 25,
  'GITLAB_RRT': 25,
  'GITLAB_RUNNER_AUTHENTICATION_TOKEN': 35,
  'GITLAB_RUNNER_AUTHENTICATION_TOKEN_ROUTABLE': 35,
  'GITLAB_SCIM_TOKEN': 35,
  'GITLAB_SESSION_COOKIE': 25,
  'GITTER_ACCESS_TOKEN': 35,
  'GOCARDLESS_API_TOKEN': 35,
  'GRAFANA_API_KEY': 35,
  'GRAFANA_CLOUD_API_TOKEN': 35,
  'GRAFANA_SERVICE_ACCOUNT_TOKEN': 35,
  'GREPTILE_API_KEY': 35,
  'GROQ_API_KEY': 35,
  'HARNESS_API_KEY': 35,
  'HASHICORP_TF_API_TOKEN': 35,
  'HASHICORP_TF_PASSWORD': 40,
  'HEROKU_API_KEY': 35,
  'HUBSPOT_API_KEY': 35,
  'HUGGINGFACE_ACCESS_TOKEN': 35,
  'HUGGINGFACE_ORGANIZATION_API_TOKEN': 35,
  'INFRACOST_API_TOKEN': 35,
  'INTERCOM_API_KEY': 35,
  'INTRA42_CLIENT_SECRET': 40,
  'JFROG_API_KEY': 35,
  'JFROG_IDENTITY_TOKEN': 35,
  'JWT': 25,
  'KRAKEN_ACCESS_TOKEN': 35,
  'KUBERNETES_SECRET_YAML': 40,
  'KUCOIN_ACCESS_TOKEN': 35,
  'KUCOIN_SECRET_KEY': 40,
  'LAUNCHDARKLY_ACCESS_TOKEN': 35,
  'LINEAR_API_KEY': 35,
  'LINEAR_CLIENT_SECRET': 40,
  'LINKEDIN_CLIENT_ID': 15,
  'LINKEDIN_CLIENT_SECRET': 40,
  'LOB_API_KEY': 35,
  'LOB_PUB_API_KEY': 35,
  'LOOKER_CLIENT_ID': 15,
  'LOOKER_CLIENT_SECRET': 40,
  'MAILCHIMP_API_KEY': 35,
  'MAILGUN_PRIVATE_API_TOKEN': 40,
  'MAILGUN_PUB_KEY': 15,
  'MAILGUN_SIGNING_KEY': 40,
  'MAPBOX_API_TOKEN': 35,
  'MATTERMOST_ACCESS_TOKEN': 35,
  'MAXMIND_LICENSE_KEY': 25,
  'MESSAGEBIRD_API_TOKEN': 35,
  'MESSAGEBIRD_CLIENT_ID': 15,
  'MICROSOFT_TEAMS_WEBHOOK': 25,
  'MISTRAL_API_KEY': 35,
  'NETLIFY_ACCESS_TOKEN': 35,
  'NEW_RELIC_BROWSER_API_TOKEN': 35,
  'NEW_RELIC_INSERT_KEY': 25,
  'NEW_RELIC_USER_API_ID': 15,
  'NEW_RELIC_USER_API_KEY': 35,
  'NOTION_API_TOKEN': 35,
  'NPM_ACCESS_TOKEN': 35,
  'NUGET_CONFIG_PASSWORD': 40,
  'NVIDIA_API_KEY': 35,
  'NYTIMES_ACCESS_TOKEN': 35,
  'OCTOPUS_DEPLOY_API_KEY': 35,
  'OKTA_ACCESS_TOKEN': 35,
  'OLLAMA_API_KEY': 35,
  'OPENAI_API_KEY': 35,
  'OPENROUTER_API_KEY': 35,
  'OPENSHIFT_USER_TOKEN': 35,
  'PLAID_API_TOKEN': 35,
  'PLAID_CLIENT_ID': 15,
  'PLAID_SECRET_KEY': 40,
  'PLANETSCALE_API_TOKEN': 35,
  'PLANETSCALE_ID': 15,
  'PLANETSCALE_OAUTH_TOKEN': 35,
  'PLANETSCALE_PASSWORD': 40,
  'POSTHOG_PERSONAL_API_KEY': 35,
  'POSTHOG_PROJECT_API_KEY': 35,
  'POSTMAN_API_TOKEN': 35,
  'PREFECT_API_TOKEN': 35,
  'PRIVATEAI_API_TOKEN': 40,
  'PULUMI_API_TOKEN': 35,
  'PYPI_UPLOAD_TOKEN': 35,
  'RAPIDAPI_ACCESS_TOKEN': 35,
  'README_API_TOKEN': 35,
  'REPLICATE_API_TOKEN': 35,
  'RUBYGEMS_API_TOKEN': 35,
  'SCALINGO_API_TOKEN': 35,
  'SENDBIRD_ACCESS_ID': 15,
  'SENDBIRD_ACCESS_TOKEN': 35,
  'SENDGRID_API_TOKEN': 35,
  'SENDINBLUE_API_TOKEN': 35,
  'SENTRY_ACCESS_TOKEN': 35,
  'SENTRY_ORG_TOKEN': 35,
  'SENTRY_USER_TOKEN': 35,
  'SETTLEMINT_APPLICATION_ACCESS_TOKEN': 35,
  'SETTLEMINT_PERSONAL_ACCESS_TOKEN': 35,
  'SETTLEMINT_SERVICE_ACCESS_TOKEN': 35,
  'SHIPPO_API_TOKEN': 35,
  'SHOPIFY_ACCESS_TOKEN': 35,
  'SHOPIFY_CUSTOM_ACCESS_TOKEN': 35,
  'SHOPIFY_PRIVATE_APP_ACCESS_TOKEN': 40,
  'SHOPIFY_SHARED_SECRET': 40,
  'SIDEKIQ_SECRET': 40,
  'SIDEKIQ_SENSITIVE_URL': 25,
  'SLACK_APP_TOKEN': 35,
  'SLACK_BOT_TOKEN': 35,
  'SLACK_CONFIG_ACCESS_TOKEN': 35,
  'SLACK_CONFIG_REFRESH_TOKEN': 35,
  'SLACK_LEGACY_BOT_TOKEN': 35,
  'SLACK_LEGACY_TOKEN': 35,
  'SLACK_LEGACY_WORKSPACE_TOKEN': 35,
  'SLACK_USER_TOKEN': 35,
  'SLACK_WEBHOOK_URL': 25,
  'SNYK_API_TOKEN': 35,
  'SONAR_API_TOKEN': 35,
  'SOURCEGRAPH_ACCESS_TOKEN': 35,
  'SQUARE_ACCESS_TOKEN': 35,
  'SQUARESPACE_ACCESS_TOKEN': 35,
  'STABILITY_AI_API_KEY': 35,
  'STRIPE_ACCESS_TOKEN': 35,
  'SUMOLOGIC_ACCESS_ID': 15,
  'SUMOLOGIC_ACCESS_TOKEN': 35,
  'TELEGRAM_BOT_API_TOKEN': 35,
  'TOGETHERAI_API_KEY': 35,
  'TRAVISCI_ACCESS_TOKEN': 35,
  'TWILIO_API_KEY': 35,
  'TWITCH_API_TOKEN': 35,
  'TWITTER_ACCESS_SECRET': 40,
  'TWITTER_ACCESS_TOKEN': 35,
  'TWITTER_API_KEY': 35,
  'TWITTER_API_SECRET': 40,
  'TWITTER_BEARER_TOKEN': 35,
  'TYPEFORM_API_TOKEN': 35,
  'VAULT_BATCH_TOKEN': 35,
  'VAULT_SERVICE_TOKEN': 35,
  'VERCEL_AI_GATEWAY_KEY': 25,
  'VERCEL_API_TOKEN': 35,
  'VERCEL_APP_ACCESS_TOKEN': 35,
  'VERCEL_APP_REFRESH_TOKEN': 35,
  'VERCEL_INTEGRATION_TOKEN': 35,
  'VERCEL_PERSONAL_ACCESS_TOKEN': 35,
  'WEIGHTS_AND_BIASES_API_KEY': 35,
  'XAI_API_KEY': 35,
  'YANDEX_ACCESS_TOKEN': 35,
  'YANDEX_API_KEY': 35,
  'YANDEX_AWS_ACCESS_TOKEN': 35,
  'ZENDESK_SECRET_KEY': 40,
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

