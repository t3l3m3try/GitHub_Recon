export interface MacroCategory {
  id: string;
  name: string;
  icon: string;
  color: string;
}

export const MACRO_CATEGORIES: Record<string, MacroCategory> = {
  emails: { id: 'emails', name: 'Emails', icon: '', color: '#14B8A6' },
  ai_ml: { id: 'ai_ml', name: 'AI & Machine Learning', icon: '', color: '#8B5CF6' },
  database_storage: { id: 'database_storage', name: 'Database & Storage', icon: '', color: '#10B981' },
  payment_fintech: { id: 'payment_fintech', name: 'Payment & Fintech', icon: '', color: '#F59E0B' },
  marketing_ecommerce: { id: 'marketing_ecommerce', name: 'Marketing & E-commerce', icon: '', color: '#EC4899' },
  devops_ci_cd: { id: 'devops_ci_cd', name: 'DevOps & CI/CD', icon: '', color: '#3B82F6' },
  saas_collab: { id: 'saas_collab', name: 'SaaS & Collaboration', icon: '', color: '#06B6D4' },
  cloud_infra: { id: 'cloud_infra', name: 'Cloud Infrastructure', icon: '', color: '#EF4444' },
  credentials_auth: { id: 'credentials_auth', name: 'Credentials & Auth', icon: '', color: '#6B7280' }
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

export const ALL_KNOWN_TYPES = [
  {
    "value": "EMAIL",
    "label": "Email"
  },
  {
    "value": "AWS_ACCESS_KEY",
    "label": "AWS Access Key"
  },
  {
    "value": "AWS_SECRET_KEY",
    "label": "AWS Secret Key"
  },
  {
    "value": "GITHUB_TOKEN",
    "label": "GitHub Token"
  },
  {
    "value": "GITLAB_TOKEN",
    "label": "GitLab Token"
  },
  {
    "value": "BITBUCKET_TOKEN",
    "label": "Bitbucket Token"
  },
  {
    "value": "API_KEY",
    "label": "API Key"
  },
  {
    "value": "GOOGLE_API_KEY",
    "label": "Google API Key"
  },
  {
    "value": "FIREBASE_KEY",
    "label": "Firebase Key"
  },
  {
    "value": "AZURE_KEY",
    "label": "Azure Key"
  },
  {
    "value": "HEROKU_KEY",
    "label": "Heroku Key"
  },
  {
    "value": "CLOUDFLARE_KEY",
    "label": "Cloudflare Key"
  },
  {
    "value": "CREDENTIAL_PAIR",
    "label": "Credential Pair (Email+Pass)"
  },
  {
    "value": "PASSWORD",
    "label": "Password"
  },
  {
    "value": "OAUTH_TOKEN",
    "label": "OAuth Token"
  },
  {
    "value": "BEARER_TOKEN",
    "label": "Bearer Token"
  },
  {
    "value": "JWT_SECRET",
    "label": "JWT Token"
  },
  {
    "value": "PRIVATE_KEY",
    "label": "Private Key"
  },
  {
    "value": "SSH_KEY",
    "label": "SSH Key"
  },
  {
    "value": "PGP_KEY",
    "label": "PGP Private Key"
  },
  {
    "value": "STRIPE_KEY",
    "label": "Stripe Key"
  },
  {
    "value": "SQUARE_KEY",
    "label": "Square Key"
  },
  {
    "value": "PAYPAL_TOKEN",
    "label": "PayPal Token"
  },
  {
    "value": "SLACK_TOKEN",
    "label": "Slack Token"
  },
  {
    "value": "SLACK_WEBHOOK",
    "label": "Slack Webhook"
  },
  {
    "value": "SENDGRID_KEY",
    "label": "SendGrid Key"
  },
  {
    "value": "MAILCHIMP_KEY",
    "label": "MailChimp Key"
  },
  {
    "value": "TWILIO_KEY",
    "label": "Twilio Key"
  },
  {
    "value": "SHOPIFY_KEY",
    "label": "Shopify Key"
  },
  {
    "value": "DATABASE_URL",
    "label": "Database URL"
  },
  {
    "value": "CONNECTION_STRING",
    "label": "Connection String"
  },
  {
    "value": "NPMRC_AUTH",
    "label": "NPM Auth Token"
  },
  {
    "value": "NPM_TOKEN",
    "label": "NPM Token"
  },
  {
    "value": "DOCKER_PASSWORD",
    "label": "Docker Password"
  },
  {
    "value": "DATADOG_KEY",
    "label": "Datadog Key"
  },
  {
    "value": "GENERIC_SECRET",
    "label": "Generic Secret"
  },
  {
    "value": "1PASSWORD_SECRET_KEY",
    "label": "1Password Secret Key"
  },
  {
    "value": "1PASSWORD_SERVICE_ACCOUNT_TOKEN",
    "label": "1Password Service Account Token"
  },
  {
    "value": "ADAFRUIT_API_KEY",
    "label": "Adafruit Api Key"
  },
  {
    "value": "ADOBE_CLIENT_ID",
    "label": "Adobe Client Id"
  },
  {
    "value": "ADOBE_CLIENT_SECRET",
    "label": "Adobe Client Secret"
  },
  {
    "value": "AGE_SECRET_KEY",
    "label": "Age Secret Key"
  },
  {
    "value": "AIRTABLE_API_KEY",
    "label": "Airtable Api Key"
  },
  {
    "value": "AIRTABLE_PERSONNAL_ACCESS_TOKEN",
    "label": "Airtable Personnal Access Token"
  },
  {
    "value": "ALGOLIA_API_KEY",
    "label": "Algolia Api Key"
  },
  {
    "value": "ALIBABA_ACCESS_KEY_ID",
    "label": "Alibaba Access Key Id"
  },
  {
    "value": "ALIBABA_SECRET_KEY",
    "label": "Alibaba Secret Key"
  },
  {
    "value": "ANTHROPIC_ADMIN_API_KEY",
    "label": "Anthropic Admin Api Key"
  },
  {
    "value": "ANTHROPIC_API_KEY",
    "label": "Anthropic Api Key"
  },
  {
    "value": "ARTIFACTORY_API_KEY",
    "label": "Artifactory Api Key"
  },
  {
    "value": "ARTIFACTORY_REFERENCE_TOKEN",
    "label": "Artifactory Reference Token"
  },
  {
    "value": "ASANA_CLIENT_ID",
    "label": "Asana Client Id"
  },
  {
    "value": "ASANA_CLIENT_SECRET",
    "label": "Asana Client Secret"
  },
  {
    "value": "ASSEMBLYAI_API_KEY",
    "label": "Assemblyai Api Key"
  },
  {
    "value": "ATLASSIAN_API_TOKEN",
    "label": "Atlassian Api Token"
  },
  {
    "value": "AUTHRESS_SERVICE_CLIENT_ACCESS_KEY",
    "label": "Authress Service Client Access Key"
  },
  {
    "value": "AWS_ACCESS_TOKEN",
    "label": "Aws Access Token"
  },
  {
    "value": "AWS_AMAZON_BEDROCK_API_KEY_LONG_LIVED",
    "label": "Aws Amazon Bedrock Api Key Long Lived"
  },
  {
    "value": "AWS_AMAZON_BEDROCK_API_KEY_SHORT_LIVED",
    "label": "Aws Amazon Bedrock Api Key Short Lived"
  },
  {
    "value": "AWS_SECRET_ACCESS_KEY",
    "label": "Aws Secret Access Key"
  },
  {
    "value": "AZURE_AD_CLIENT_SECRET",
    "label": "Azure Ad Client Secret"
  },
  {
    "value": "BEAMER_API_TOKEN",
    "label": "Beamer Api Token"
  },
  {
    "value": "BITBUCKET_CLIENT_ID",
    "label": "Bitbucket Client Id"
  },
  {
    "value": "BITBUCKET_CLIENT_SECRET",
    "label": "Bitbucket Client Secret"
  },
  {
    "value": "BITTREX_ACCESS_KEY",
    "label": "Bittrex Access Key"
  },
  {
    "value": "BITTREX_SECRET_KEY",
    "label": "Bittrex Secret Key"
  },
  {
    "value": "CEREBRAS_API_KEY",
    "label": "Cerebras Api Key"
  },
  {
    "value": "CISCO_MERAKI_API_KEY",
    "label": "Cisco Meraki Api Key"
  },
  {
    "value": "CLICKHOUSE_CLOUD_API_SECRET_KEY",
    "label": "Clickhouse Cloud Api Secret Key"
  },
  {
    "value": "CLOJARS_API_TOKEN",
    "label": "Clojars Api Token"
  },
  {
    "value": "CLOUDFLARE_API_KEY",
    "label": "Cloudflare Api Key"
  },
  {
    "value": "CLOUDFLARE_GLOBAL_API_KEY",
    "label": "Cloudflare Global Api Key"
  },
  {
    "value": "CLOUDFLARE_ORIGIN_CA_KEY",
    "label": "Cloudflare Origin Ca Key"
  },
  {
    "value": "CODECOV_ACCESS_TOKEN",
    "label": "Codecov Access Token"
  },
  {
    "value": "COHERE_API_TOKEN",
    "label": "Cohere Api Token"
  },
  {
    "value": "COINBASE_ACCESS_TOKEN",
    "label": "Coinbase Access Token"
  },
  {
    "value": "CONFLUENT_ACCESS_TOKEN",
    "label": "Confluent Access Token"
  },
  {
    "value": "CONFLUENT_SECRET_KEY",
    "label": "Confluent Secret Key"
  },
  {
    "value": "CONTENTFUL_DELIVERY_API_TOKEN",
    "label": "Contentful Delivery Api Token"
  },
  {
    "value": "CURL_AUTH_HEADER",
    "label": "Curl Auth Header"
  },
  {
    "value": "CURL_AUTH_USER",
    "label": "Curl Auth User"
  },
  {
    "value": "CURSOR_API_KEY",
    "label": "Cursor Api Key"
  },
  {
    "value": "DATABRICKS_API_TOKEN",
    "label": "Databricks Api Token"
  },
  {
    "value": "DATADOG_ACCESS_TOKEN",
    "label": "Datadog Access Token"
  },
  {
    "value": "DEEPGRAM_API_KEY",
    "label": "Deepgram Api Key"
  },
  {
    "value": "DEEPSEEK_API_KEY",
    "label": "Deepseek Api Key"
  },
  {
    "value": "DEFINED_NETWORKING_API_TOKEN",
    "label": "Defined Networking Api Token"
  },
  {
    "value": "DIGITALOCEAN_ACCESS_TOKEN",
    "label": "Digitalocean Access Token"
  },
  {
    "value": "DIGITALOCEAN_PAT",
    "label": "Digitalocean Pat"
  },
  {
    "value": "DIGITALOCEAN_REFRESH_TOKEN",
    "label": "Digitalocean Refresh Token"
  },
  {
    "value": "DISCORD_API_TOKEN",
    "label": "Discord Api Token"
  },
  {
    "value": "DISCORD_CLIENT_ID",
    "label": "Discord Client Id"
  },
  {
    "value": "DISCORD_CLIENT_SECRET",
    "label": "Discord Client Secret"
  },
  {
    "value": "DOPPLER_API_TOKEN",
    "label": "Doppler Api Token"
  },
  {
    "value": "DRONECI_ACCESS_TOKEN",
    "label": "Droneci Access Token"
  },
  {
    "value": "DROPBOX_API_TOKEN",
    "label": "Dropbox Api Token"
  },
  {
    "value": "DROPBOX_LONG_LIVED_API_TOKEN",
    "label": "Dropbox Long Lived Api Token"
  },
  {
    "value": "DROPBOX_SHORT_LIVED_API_TOKEN",
    "label": "Dropbox Short Lived Api Token"
  },
  {
    "value": "DUFFEL_API_TOKEN",
    "label": "Duffel Api Token"
  },
  {
    "value": "DYNATRACE_API_TOKEN",
    "label": "Dynatrace Api Token"
  },
  {
    "value": "EASYPOST_API_TOKEN",
    "label": "Easypost Api Token"
  },
  {
    "value": "EASYPOST_TEST_API_TOKEN",
    "label": "Easypost Test Api Token"
  },
  {
    "value": "ELEVENLABS_API_KEY",
    "label": "Elevenlabs Api Key"
  },
  {
    "value": "ENDORLABS_API_KEY",
    "label": "Endorlabs Api Key"
  },
  {
    "value": "ENDORLABS_API_SECRET",
    "label": "Endorlabs Api Secret"
  },
  {
    "value": "ETSY_ACCESS_TOKEN",
    "label": "Etsy Access Token"
  },
  {
    "value": "FACEBOOK_ACCESS_TOKEN",
    "label": "Facebook Access Token"
  },
  {
    "value": "FACEBOOK_PAGE_ACCESS_TOKEN",
    "label": "Facebook Page Access Token"
  },
  {
    "value": "FACEBOOK_SECRET",
    "label": "Facebook Secret"
  },
  {
    "value": "FASTLY_API_TOKEN",
    "label": "Fastly Api Token"
  },
  {
    "value": "FINICITY_API_TOKEN",
    "label": "Finicity Api Token"
  },
  {
    "value": "FINICITY_CLIENT_SECRET",
    "label": "Finicity Client Secret"
  },
  {
    "value": "FINNHUB_ACCESS_TOKEN",
    "label": "Finnhub Access Token"
  },
  {
    "value": "FLICKR_ACCESS_TOKEN",
    "label": "Flickr Access Token"
  },
  {
    "value": "FLUTTERWAVE_ENCRYPTION_KEY",
    "label": "Flutterwave Encryption Key"
  },
  {
    "value": "FLUTTERWAVE_PUBLIC_KEY",
    "label": "Flutterwave Public Key"
  },
  {
    "value": "FLUTTERWAVE_SECRET_KEY",
    "label": "Flutterwave Secret Key"
  },
  {
    "value": "FLYIO_ACCESS_TOKEN",
    "label": "Flyio Access Token"
  },
  {
    "value": "FRAMEIO_API_TOKEN",
    "label": "Frameio Api Token"
  },
  {
    "value": "FREEMIUS_SECRET_KEY",
    "label": "Freemius Secret Key"
  },
  {
    "value": "FRESHBOOKS_ACCESS_TOKEN",
    "label": "Freshbooks Access Token"
  },
  {
    "value": "GCP_API_KEY",
    "label": "Gcp Api Key"
  },
  {
    "value": "GITEA_ACCESS_TOKEN",
    "label": "Gitea Access Token"
  },
  {
    "value": "GITHUB_APP_TOKEN",
    "label": "Github App Token"
  },
  {
    "value": "GITHUB_FINE_GRAINED_PAT",
    "label": "Github Fine Grained Pat"
  },
  {
    "value": "GITHUB_OAUTH",
    "label": "Github Oauth"
  },
  {
    "value": "GITHUB_PAT",
    "label": "Github Pat"
  },
  {
    "value": "GITHUB_REFRESH_TOKEN",
    "label": "Github Refresh Token"
  },
  {
    "value": "GITLAB_CICD_JOB_TOKEN",
    "label": "Gitlab Cicd Job Token"
  },
  {
    "value": "GITLAB_DEPLOY_TOKEN",
    "label": "Gitlab Deploy Token"
  },
  {
    "value": "GITLAB_FEATURE_FLAG_CLIENT_TOKEN",
    "label": "Gitlab Feature Flag Client Token"
  },
  {
    "value": "GITLAB_FEED_TOKEN",
    "label": "Gitlab Feed Token"
  },
  {
    "value": "GITLAB_INCOMING_MAIL_TOKEN",
    "label": "Gitlab Incoming Mail Token"
  },
  {
    "value": "GITLAB_KUBERNETES_AGENT_TOKEN",
    "label": "Gitlab Kubernetes Agent Token"
  },
  {
    "value": "GITLAB_OAUTH_APP_SECRET",
    "label": "Gitlab Oauth App Secret"
  },
  {
    "value": "GITLAB_PAT",
    "label": "Gitlab Pat"
  },
  {
    "value": "GITLAB_PAT_ROUTABLE",
    "label": "Gitlab Pat Routable"
  },
  {
    "value": "GITLAB_PTT",
    "label": "Gitlab Ptt"
  },
  {
    "value": "GITLAB_RRT",
    "label": "Gitlab Rrt"
  },
  {
    "value": "GITLAB_RUNNER_AUTHENTICATION_TOKEN",
    "label": "Gitlab Runner Authentication Token"
  },
  {
    "value": "GITLAB_RUNNER_AUTHENTICATION_TOKEN_ROUTABLE",
    "label": "Gitlab Runner Authentication Token Routable"
  },
  {
    "value": "GITLAB_SCIM_TOKEN",
    "label": "Gitlab Scim Token"
  },
  {
    "value": "GITLAB_SESSION_COOKIE",
    "label": "Gitlab Session Cookie"
  },
  {
    "value": "GITTER_ACCESS_TOKEN",
    "label": "Gitter Access Token"
  },
  {
    "value": "GOCARDLESS_API_TOKEN",
    "label": "Gocardless Api Token"
  },
  {
    "value": "GRAFANA_API_KEY",
    "label": "Grafana Api Key"
  },
  {
    "value": "GRAFANA_CLOUD_API_TOKEN",
    "label": "Grafana Cloud Api Token"
  },
  {
    "value": "GRAFANA_SERVICE_ACCOUNT_TOKEN",
    "label": "Grafana Service Account Token"
  },
  {
    "value": "GREPTILE_API_KEY",
    "label": "Greptile Api Key"
  },
  {
    "value": "GROQ_API_KEY",
    "label": "Groq Api Key"
  },
  {
    "value": "HARNESS_API_KEY",
    "label": "Harness Api Key"
  },
  {
    "value": "HASHICORP_TF_API_TOKEN",
    "label": "Hashicorp Tf Api Token"
  },
  {
    "value": "HASHICORP_TF_PASSWORD",
    "label": "Hashicorp Tf Password"
  },
  {
    "value": "HEROKU_API_KEY",
    "label": "Heroku Api Key"
  },
  {
    "value": "HUBSPOT_API_KEY",
    "label": "Hubspot Api Key"
  },
  {
    "value": "HUGGINGFACE_ACCESS_TOKEN",
    "label": "Huggingface Access Token"
  },
  {
    "value": "HUGGINGFACE_ORGANIZATION_API_TOKEN",
    "label": "Huggingface Organization Api Token"
  },
  {
    "value": "INFRACOST_API_TOKEN",
    "label": "Infracost Api Token"
  },
  {
    "value": "INTERCOM_API_KEY",
    "label": "Intercom Api Key"
  },
  {
    "value": "INTRA42_CLIENT_SECRET",
    "label": "Intra42 Client Secret"
  },
  {
    "value": "JFROG_API_KEY",
    "label": "Jfrog Api Key"
  },
  {
    "value": "JFROG_IDENTITY_TOKEN",
    "label": "Jfrog Identity Token"
  },
  {
    "value": "JWT",
    "label": "Jwt"
  },
  {
    "value": "KRAKEN_ACCESS_TOKEN",
    "label": "Kraken Access Token"
  },
  {
    "value": "KUBERNETES_SECRET_YAML",
    "label": "Kubernetes Secret Yaml"
  },
  {
    "value": "KUCOIN_ACCESS_TOKEN",
    "label": "Kucoin Access Token"
  },
  {
    "value": "KUCOIN_SECRET_KEY",
    "label": "Kucoin Secret Key"
  },
  {
    "value": "LAUNCHDARKLY_ACCESS_TOKEN",
    "label": "Launchdarkly Access Token"
  },
  {
    "value": "LINEAR_API_KEY",
    "label": "Linear Api Key"
  },
  {
    "value": "LINEAR_CLIENT_SECRET",
    "label": "Linear Client Secret"
  },
  {
    "value": "LINKEDIN_CLIENT_ID",
    "label": "Linkedin Client Id"
  },
  {
    "value": "LINKEDIN_CLIENT_SECRET",
    "label": "Linkedin Client Secret"
  },
  {
    "value": "LOB_API_KEY",
    "label": "Lob Api Key"
  },
  {
    "value": "LOB_PUB_API_KEY",
    "label": "Lob Pub Api Key"
  },
  {
    "value": "LOOKER_CLIENT_ID",
    "label": "Looker Client Id"
  },
  {
    "value": "LOOKER_CLIENT_SECRET",
    "label": "Looker Client Secret"
  },
  {
    "value": "MAILCHIMP_API_KEY",
    "label": "Mailchimp Api Key"
  },
  {
    "value": "MAILGUN_PRIVATE_API_TOKEN",
    "label": "Mailgun Private Api Token"
  },
  {
    "value": "MAILGUN_PUB_KEY",
    "label": "Mailgun Pub Key"
  },
  {
    "value": "MAILGUN_SIGNING_KEY",
    "label": "Mailgun Signing Key"
  },
  {
    "value": "MAPBOX_API_TOKEN",
    "label": "Mapbox Api Token"
  },
  {
    "value": "MATTERMOST_ACCESS_TOKEN",
    "label": "Mattermost Access Token"
  },
  {
    "value": "MAXMIND_LICENSE_KEY",
    "label": "Maxmind License Key"
  },
  {
    "value": "MESSAGEBIRD_API_TOKEN",
    "label": "Messagebird Api Token"
  },
  {
    "value": "MESSAGEBIRD_CLIENT_ID",
    "label": "Messagebird Client Id"
  },
  {
    "value": "MICROSOFT_TEAMS_WEBHOOK",
    "label": "Microsoft Teams Webhook"
  },
  {
    "value": "MISTRAL_API_KEY",
    "label": "Mistral Api Key"
  },
  {
    "value": "NETLIFY_ACCESS_TOKEN",
    "label": "Netlify Access Token"
  },
  {
    "value": "NEW_RELIC_BROWSER_API_TOKEN",
    "label": "New Relic Browser Api Token"
  },
  {
    "value": "NEW_RELIC_INSERT_KEY",
    "label": "New Relic Insert Key"
  },
  {
    "value": "NEW_RELIC_USER_API_ID",
    "label": "New Relic User Api Id"
  },
  {
    "value": "NEW_RELIC_USER_API_KEY",
    "label": "New Relic User Api Key"
  },
  {
    "value": "NOTION_API_TOKEN",
    "label": "Notion Api Token"
  },
  {
    "value": "NPM_ACCESS_TOKEN",
    "label": "Npm Access Token"
  },
  {
    "value": "NUGET_CONFIG_PASSWORD",
    "label": "Nuget Config Password"
  },
  {
    "value": "NVIDIA_API_KEY",
    "label": "Nvidia Api Key"
  },
  {
    "value": "NYTIMES_ACCESS_TOKEN",
    "label": "Nytimes Access Token"
  },
  {
    "value": "OCTOPUS_DEPLOY_API_KEY",
    "label": "Octopus Deploy Api Key"
  },
  {
    "value": "OKTA_ACCESS_TOKEN",
    "label": "Okta Access Token"
  },
  {
    "value": "OLLAMA_API_KEY",
    "label": "Ollama Api Key"
  },
  {
    "value": "OPENAI_API_KEY",
    "label": "Openai Api Key"
  },
  {
    "value": "OPENROUTER_API_KEY",
    "label": "Openrouter Api Key"
  },
  {
    "value": "OPENSHIFT_USER_TOKEN",
    "label": "Openshift User Token"
  },
  {
    "value": "PLAID_API_TOKEN",
    "label": "Plaid Api Token"
  },
  {
    "value": "PLAID_CLIENT_ID",
    "label": "Plaid Client Id"
  },
  {
    "value": "PLAID_SECRET_KEY",
    "label": "Plaid Secret Key"
  },
  {
    "value": "PLANETSCALE_API_TOKEN",
    "label": "Planetscale Api Token"
  },
  {
    "value": "PLANETSCALE_ID",
    "label": "Planetscale Id"
  },
  {
    "value": "PLANETSCALE_OAUTH_TOKEN",
    "label": "Planetscale Oauth Token"
  },
  {
    "value": "PLANETSCALE_PASSWORD",
    "label": "Planetscale Password"
  },
  {
    "value": "POSTHOG_PERSONAL_API_KEY",
    "label": "Posthog Personal Api Key"
  },
  {
    "value": "POSTHOG_PROJECT_API_KEY",
    "label": "Posthog Project Api Key"
  },
  {
    "value": "POSTMAN_API_TOKEN",
    "label": "Postman Api Token"
  },
  {
    "value": "PREFECT_API_TOKEN",
    "label": "Prefect Api Token"
  },
  {
    "value": "PRIVATEAI_API_TOKEN",
    "label": "Privateai Api Token"
  },
  {
    "value": "PULUMI_API_TOKEN",
    "label": "Pulumi Api Token"
  },
  {
    "value": "PYPI_UPLOAD_TOKEN",
    "label": "Pypi Upload Token"
  },
  {
    "value": "RAPIDAPI_ACCESS_TOKEN",
    "label": "Rapidapi Access Token"
  },
  {
    "value": "README_API_TOKEN",
    "label": "Readme Api Token"
  },
  {
    "value": "REPLICATE_API_TOKEN",
    "label": "Replicate Api Token"
  },
  {
    "value": "RUBYGEMS_API_TOKEN",
    "label": "Rubygems Api Token"
  },
  {
    "value": "SCALINGO_API_TOKEN",
    "label": "Scalingo Api Token"
  },
  {
    "value": "SENDBIRD_ACCESS_ID",
    "label": "Sendbird Access Id"
  },
  {
    "value": "SENDBIRD_ACCESS_TOKEN",
    "label": "Sendbird Access Token"
  },
  {
    "value": "SENDGRID_API_TOKEN",
    "label": "Sendgrid Api Token"
  },
  {
    "value": "SENDINBLUE_API_TOKEN",
    "label": "Sendinblue Api Token"
  },
  {
    "value": "SENTRY_ACCESS_TOKEN",
    "label": "Sentry Access Token"
  },
  {
    "value": "SENTRY_ORG_TOKEN",
    "label": "Sentry Org Token"
  },
  {
    "value": "SENTRY_USER_TOKEN",
    "label": "Sentry User Token"
  },
  {
    "value": "SETTLEMINT_APPLICATION_ACCESS_TOKEN",
    "label": "Settlemint Application Access Token"
  },
  {
    "value": "SETTLEMINT_PERSONAL_ACCESS_TOKEN",
    "label": "Settlemint Personal Access Token"
  },
  {
    "value": "SETTLEMINT_SERVICE_ACCESS_TOKEN",
    "label": "Settlemint Service Access Token"
  },
  {
    "value": "SHIPPO_API_TOKEN",
    "label": "Shippo Api Token"
  },
  {
    "value": "SHOPIFY_ACCESS_TOKEN",
    "label": "Shopify Access Token"
  },
  {
    "value": "SHOPIFY_CUSTOM_ACCESS_TOKEN",
    "label": "Shopify Custom Access Token"
  },
  {
    "value": "SHOPIFY_PRIVATE_APP_ACCESS_TOKEN",
    "label": "Shopify Private App Access Token"
  },
  {
    "value": "SHOPIFY_SHARED_SECRET",
    "label": "Shopify Shared Secret"
  },
  {
    "value": "SIDEKIQ_SECRET",
    "label": "Sidekiq Secret"
  },
  {
    "value": "SIDEKIQ_SENSITIVE_URL",
    "label": "Sidekiq Sensitive Url"
  },
  {
    "value": "SLACK_APP_TOKEN",
    "label": "Slack App Token"
  },
  {
    "value": "SLACK_BOT_TOKEN",
    "label": "Slack Bot Token"
  },
  {
    "value": "SLACK_CONFIG_ACCESS_TOKEN",
    "label": "Slack Config Access Token"
  },
  {
    "value": "SLACK_CONFIG_REFRESH_TOKEN",
    "label": "Slack Config Refresh Token"
  },
  {
    "value": "SLACK_LEGACY_BOT_TOKEN",
    "label": "Slack Legacy Bot Token"
  },
  {
    "value": "SLACK_LEGACY_TOKEN",
    "label": "Slack Legacy Token"
  },
  {
    "value": "SLACK_LEGACY_WORKSPACE_TOKEN",
    "label": "Slack Legacy Workspace Token"
  },
  {
    "value": "SLACK_USER_TOKEN",
    "label": "Slack User Token"
  },
  {
    "value": "SLACK_WEBHOOK_URL",
    "label": "Slack Webhook Url"
  },
  {
    "value": "SNYK_API_TOKEN",
    "label": "Snyk Api Token"
  },
  {
    "value": "SONAR_API_TOKEN",
    "label": "Sonar Api Token"
  },
  {
    "value": "SOURCEGRAPH_ACCESS_TOKEN",
    "label": "Sourcegraph Access Token"
  },
  {
    "value": "SQUARESPACE_ACCESS_TOKEN",
    "label": "Squarespace Access Token"
  },
  {
    "value": "SQUARE_ACCESS_TOKEN",
    "label": "Square Access Token"
  },
  {
    "value": "STABILITY_AI_API_KEY",
    "label": "Stability Ai Api Key"
  },
  {
    "value": "STRIPE_ACCESS_TOKEN",
    "label": "Stripe Access Token"
  },
  {
    "value": "SUMOLOGIC_ACCESS_ID",
    "label": "Sumologic Access Id"
  },
  {
    "value": "SUMOLOGIC_ACCESS_TOKEN",
    "label": "Sumologic Access Token"
  },
  {
    "value": "TELEGRAM_BOT_API_TOKEN",
    "label": "Telegram Bot Api Token"
  },
  {
    "value": "TOGETHERAI_API_KEY",
    "label": "Togetherai Api Key"
  },
  {
    "value": "TRAVISCI_ACCESS_TOKEN",
    "label": "Travisci Access Token"
  },
  {
    "value": "TWILIO_API_KEY",
    "label": "Twilio Api Key"
  },
  {
    "value": "TWITCH_API_TOKEN",
    "label": "Twitch Api Token"
  },
  {
    "value": "TWITTER_ACCESS_SECRET",
    "label": "Twitter Access Secret"
  },
  {
    "value": "TWITTER_ACCESS_TOKEN",
    "label": "Twitter Access Token"
  },
  {
    "value": "TWITTER_API_KEY",
    "label": "Twitter Api Key"
  },
  {
    "value": "TWITTER_API_SECRET",
    "label": "Twitter Api Secret"
  },
  {
    "value": "TWITTER_BEARER_TOKEN",
    "label": "Twitter Bearer Token"
  },
  {
    "value": "TYPEFORM_API_TOKEN",
    "label": "Typeform Api Token"
  },
  {
    "value": "VAULT_BATCH_TOKEN",
    "label": "Vault Batch Token"
  },
  {
    "value": "VAULT_SERVICE_TOKEN",
    "label": "Vault Service Token"
  },
  {
    "value": "VERCEL_AI_GATEWAY_KEY",
    "label": "Vercel Ai Gateway Key"
  },
  {
    "value": "VERCEL_API_TOKEN",
    "label": "Vercel Api Token"
  },
  {
    "value": "VERCEL_APP_ACCESS_TOKEN",
    "label": "Vercel App Access Token"
  },
  {
    "value": "VERCEL_APP_REFRESH_TOKEN",
    "label": "Vercel App Refresh Token"
  },
  {
    "value": "VERCEL_INTEGRATION_TOKEN",
    "label": "Vercel Integration Token"
  },
  {
    "value": "VERCEL_PERSONAL_ACCESS_TOKEN",
    "label": "Vercel Personal Access Token"
  },
  {
    "value": "WEIGHTS_AND_BIASES_API_KEY",
    "label": "Weights And Biases Api Key"
  },
  {
    "value": "XAI_API_KEY",
    "label": "Xai Api Key"
  },
  {
    "value": "YANDEX_ACCESS_TOKEN",
    "label": "Yandex Access Token"
  },
  {
    "value": "YANDEX_API_KEY",
    "label": "Yandex Api Key"
  },
  {
    "value": "YANDEX_AWS_ACCESS_TOKEN",
    "label": "Yandex Aws Access Token"
  },
  {
    "value": "ZENDESK_SECRET_KEY",
    "label": "Zendesk Secret Key"
  }
];
