export interface MacroCategory {
  id: string;
  name: string;
  color: string;
}

export const MACRO_CATEGORIES: Record<string, MacroCategory> = {
  emails: { id: 'emails', name: 'Emails', color: '#14B8A6' },
  ai_ml: { id: 'ai_ml', name: 'AI & Machine Learning', color: '#8B5CF6' },
  database_storage: { id: 'database_storage', name: 'Database & Storage', color: '#10B981' },
  payment_fintech: { id: 'payment_fintech', name: 'Payment & Fintech', color: '#F59E0B' },
  marketing_ecommerce: { id: 'marketing_ecommerce', name: 'Marketing & E-commerce', color: '#EC4899' },
  devops_ci_cd: { id: 'devops_ci_cd', name: 'DevOps & CI/CD', color: '#3B82F6' },
  saas_collab: { id: 'saas_collab', name: 'SaaS & Collaboration', color: '#06B6D4' },
  cloud_infra: { id: 'cloud_infra', name: 'Cloud Infrastructure', color: '#EF4444' },
  credentials_auth: { id: 'credentials_auth', name: 'Credentials & Auth', color: '#6B7280' }
};

export function getMacroCategory(type: string): MacroCategory {
  if (!type) return MACRO_CATEGORIES.credentials_auth;
  
  const upper = type.toUpperCase();
  
  // 0. Dedicated Emails Area
  if (upper === 'EMAIL') {
    return MACRO_CATEGORIES.emails;
  }
  
  // 1. AI & Machine Learning
  if (/OPENAI|ANTHROPIC|DEEPSEEK|GROQ|MISTRAL|CEREBRAS|STABILITY|COHERE|HUGGINGFACE|NVIDIA|OPENROUTER|XAI|BEDROCK/i.test(upper)) {
    return MACRO_CATEGORIES.ai_ml;
  }
  
  // 2. Database & Storage
  if (/DATABASE|CONNECTION|MONGO|REDIS|PLANETSCALE|POSTGRES|MYSQL|SQLSERVER|NEO4J|AIRTABLE|CLICKHOUSE|DUMP|BACKUP/i.test(upper)) {
    return MACRO_CATEGORIES.database_storage;
  }
  
  // 3. Payment & Fintech
  if (/STRIPE|SQUARE|PAYPAL|COINBASE|KRAKEN|KUCOIN|PLAID|FLUTTERWAVE|BRAINTREE|BITTREX|FINICITY/i.test(upper)) {
    return MACRO_CATEGORIES.payment_fintech;
  }
  
  // 4. Marketing & E-commerce
  if (/SENDGRID|MAILCHIMP|MAILGUN|HUBSPOT|CONTENTFUL|SHOPIFY|ACTIVE_CAMPAIGN|EASYPOST|ETSY|LOB/i.test(upper)) {
    return MACRO_CATEGORIES.marketing_ecommerce;
  }
  
  // 5. DevOps & CI/CD
  if (/GITHUB|GITLAB|BITBUCKET|NPM|DOCKER|TERRAFORM|TF_|SNYK|CODECOV|DRONECI|TRAVISCI|CIRCLECI|JENKINS|BUILDKITE|CLOJARS|HARNESS|PULUMI|OCTOPUS|PREFECT|SCALINGO|FLYIO|VERCEL|NETLIFY/i.test(upper)) {
    return MACRO_CATEGORIES.devops_ci_cd;
  }
  
  // 6. SaaS & Collaboration
  if (/SLACK|DISCORD|TELEGRAM|TWILIO|ZENDESK|ASANA|NOTION|JIRA|LINEAR|TRELLO|CONFLUENCE|SENTRY|DATADOG|NEW_RELIC|NEWRELIC|DYNATRACE|GRAFANA|POSTMAN|DOPPLER|INTERCOM|MATTERMOST|TEAMS|LOOKER|TYPEFORM|YANDEX|ZOHO|BEAMER|GREPTILE|README|REPLICATE|SONAR/i.test(upper)) {
    return MACRO_CATEGORIES.saas_collab;
  }
  
  // 7. Cloud Infrastructure
  if (/AWS|AMAZON|AZURE|GCP|GOOGLE|ALIBABA|DIGITALOCEAN|HEROKU|CLOUDFLARE|CISCO|MERAKI|MAXMIND|WANDB|INTEGRATION|FIREBASE/i.test(upper)) {
    return MACRO_CATEGORIES.cloud_infra;
  }
  
  // 8. Default fallback: Credentials & Auth (Passwords, SSH keys, general API keys, JWT, base auth)
  return MACRO_CATEGORIES.credentials_auth;
}
