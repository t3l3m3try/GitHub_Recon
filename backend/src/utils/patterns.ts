/**
 * Secret Pattern Definitions
 * Each pattern includes regex, entropy threshold, and detection confidence
 */

interface SecretPattern {
  type: string;
  pattern: RegExp;
  description: string;
  entropyThreshold?: number;
  contextKeywords?: string[];
  exampleMatch?: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Keys
  {
    type: 'AWS_ACCESS_KEY',
    pattern: /(?<![A-Za-z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g,
    description: 'AWS Access Key ID',
    entropyThreshold: 3.0,
    contextKeywords: ['aws', 'amazon', 's3', 'ec2', 'access'],
    exampleMatch: 'AKIAIOSFODNN7EXAMPLE'
  },
  {
    type: 'AWS_SECRET_KEY',
    pattern: /aws[_\-\s]*secret[_\-\s]*(?:key|access[_\-\s]*key)?['\"\s]*[:=]['\"\s]*([A-Za-z0-9/+=]{40})/gi,
    description: 'AWS Secret Access Key',
    entropyThreshold: 3.0,
    contextKeywords: ['aws', 'secret', 'access'],
    exampleMatch: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  },

  // GitHub Tokens
  {
    type: 'GITHUB_TOKEN',
    pattern: /(?<![A-Za-z0-9])(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})(?![A-Za-z0-9])/g,
    description: 'GitHub Personal Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['github', 'token', 'pat'],
    exampleMatch: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'
  },

  // Private Keys
  {
    type: 'PRIVATE_KEY',
    pattern: /-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    description: 'RSA/DSA/EC Private Key',
    entropyThreshold: 3.0,
    contextKeywords: ['private', 'key', 'ssh', 'rsa'],
    exampleMatch: '-----BEGIN RSA PRIVATE KEY-----'
  },

  // Slack Tokens
  {
    type: 'SLACK_TOKEN',
    pattern: /(?<![A-Za-z0-9])xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}(?![A-Za-z0-9])/g,
    description: 'Slack Token',
    entropyThreshold: 3.0,
    contextKeywords: ['slack', 'webhook', 'bot'],
    exampleMatch: 'xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx'
  },

  // Stripe Keys
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])(?:sk|pk)_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])/g,
    description: 'Stripe API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['stripe', 'payment', 'api'],
    exampleMatch: 'sk_live_abcdefghijklmnopqrstuvwx'
  },

  // Google API Keys
  {
    type: 'GOOGLE_API_KEY',
    pattern: /(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])/g,
    description: 'Google API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['google', 'gcp', 'api'],
    exampleMatch: 'AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz'
  },

  // JWT Tokens
  {
    type: 'JWT_SECRET',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    description: 'JWT Token',
    entropyThreshold: 3.0,
    contextKeywords: ['jwt', 'token', 'bearer'],
    exampleMatch: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  },

  // Database URLs
  {
    type: 'DATABASE_URL',
    pattern: /(postgres|postgresql|mysql|mongodb|redis):\/\/[^\s\'"<>]+/gi,
    description: 'Database Connection String',
    entropyThreshold: 3.0,
    contextKeywords: ['database', 'db', 'connection'],
    exampleMatch: 'postgresql://user:password@host:5432/database'
  },

  // Azure Keys
  {
    type: 'AZURE_KEY',
    pattern: /(?<![A-Za-z0-9/+])[a-zA-Z0-9/+]{86}==/g,
    description: 'Azure Storage Key',
    entropyThreshold: 3.0,
    contextKeywords: ['azure', 'storage', 'account'],
    exampleMatch: 'DefaultEndpointsProtocol=https;AccountName=...'
  },

  // SendGrid
  {
    type: 'SENDGRID_KEY',
    pattern: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9])/g,
    description: 'SendGrid API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['sendgrid', 'email', 'api'],
    exampleMatch: 'SG.abc123...'
  },

  // Twilio
  {
    type: 'TWILIO_KEY',
    pattern: /(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])/g,
    description: 'Twilio API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['twilio', 'sms', 'api'],
    exampleMatch: 'SKabcdef1234567890abcdef1234567890'
  },

  // NPM Token
  {
    type: 'NPM_TOKEN',
    pattern: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g,
    description: 'NPM Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['npm', 'token', 'registry'],
    exampleMatch: 'npm_1234567890abcdefghijklmnopqrstuvwxyz'
  },

  // Generic Secrets (lower priority)
  {
    type: 'GENERIC_SECRET',
    pattern: /(secret|password|passwd|pwd|token|api[_-]?key|auth[_-]?key)['\"\s]*[:=]['\"\s]*([^\s'\"<>]{8,})/gi,
    description: 'Generic Secret Pattern',
    entropyThreshold: 3.0,
    contextKeywords: ['secret', 'password', 'token', 'key'],
    exampleMatch: 'api_key: supersecretvalue123'
  },

  // Password patterns (lowered min to 2 chars to catch short passwords like "test")
  {
    type: 'PASSWORD',
    pattern: /(password|passwd|pwd)['\"\s]*[:=]['\"\s]*([^\s'\"<>]{2,})/gi,
    description: 'Password Pattern',
    entropyThreshold: 0, // No entropy filter — context ("password:") is sufficient
    contextKeywords: ['password', 'passwd', 'pwd', 'login'],
    exampleMatch: 'password: MyP@ssw0rd123'
  },

  // OAuth Tokens
  {
    type: 'OAUTH_TOKEN',
    pattern: /['\"]?access_token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-._~+/]+=*)['\"]?/gi,
    description: 'OAuth Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['oauth', 'access', 'token', 'bearer'],
    exampleMatch: 'access_token: ya29.a0AfH6SMBx...'
  },

  // SSH Private Keys
  {
    type: 'SSH_KEY',
    pattern: /-----BEGIN\s+(?:OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]{100,}?-----END\s+(?:OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    description: 'SSH Private Key',
    entropyThreshold: 3.0,
    contextKeywords: ['ssh', 'private', 'key'],
    exampleMatch: '-----BEGIN OPENSSH PRIVATE KEY-----'
  },

  // API Keys (generic high-entropy)
  {
    type: 'API_KEY',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})/gi,
    description: 'Generic API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['api', 'key', 'secret'],
    exampleMatch: 'api_key: sk_1234567890abcdef'
  },

  // Bearer Tokens
  {
    type: 'BEARER_TOKEN',
    pattern: /Bearer\s+([a-zA-Z0-9\-._~+/]+=*)/gi,
    description: 'Bearer Token',
    entropyThreshold: 3.0,
    contextKeywords: ['bearer', 'authorization', 'auth'],
    exampleMatch: 'Bearer eyJhbGciOiJIUzI1NiIs...'
  },

  // Slack Webhooks
  {
    type: 'SLACK_WEBHOOK',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]{24}/g,
    description: 'Slack Webhook URL',
    entropyThreshold: 3.0,
    contextKeywords: ['slack', 'webhook', 'hooks'],
    exampleMatch: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX'
  },

  // PayPal Braintree
  {
    type: 'PAYPAL_TOKEN',
    pattern: /access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}/gi,
    description: 'PayPal Braintree Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['paypal', 'braintree', 'token'],
    exampleMatch: 'access_token$production$abc123...'
  },

  // Square Access/Secret Keys
  {
    type: 'SQUARE_KEY',
    pattern: /(?<![A-Za-z0-9])sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}(?![A-Za-z0-9])/g,
    description: 'Square Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['square', 'payment'],
    exampleMatch: 'sq0atp-1234567890abcdef'
  },

  // Heroku API Keys
  {
    type: 'HEROKU_KEY',
    pattern: /[hH][eE][rR][oO][kK][uU].*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/g,
    description: 'Heroku API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['heroku', 'api'],
    exampleMatch: 'HEROKU_API_KEY=12345678-1234-1234-1234-123456789012'
  },

  // MailChimp API Keys
  {
    type: 'MAILCHIMP_KEY',
    pattern: /(?<![A-Za-z0-9])[0-9a-f]{32}-us[0-9]{1,2}(?![A-Za-z0-9])/gi,
    description: 'MailChimp API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['mailchimp', 'email', 'api'],
    exampleMatch: '1234567890abcdef1234567890abcdef-us19'
  },

  // Datadog API Keys (more targeted to avoid false positives)
  {
    type: 'DATADOG_KEY',
    pattern: /(?:datadog|DD_)[_-]?(?:API|APP)[_-]?KEY['\"\s]*[:=]['\"\s]*([a-f0-9]{32})/gi,
    description: 'Datadog API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['datadog', 'monitoring', 'api'],
    exampleMatch: 'DD_API_KEY=1234567890abcdef1234567890abcdef'
  },

  // Docker Hub Passwords
  {
    type: 'DOCKER_PASSWORD',
    pattern: /docker[_-]?(?:password|token)['\"\s]*[:=]['\"\s]*([^\s'\"<>]{8,})/gi,
    description: 'Docker Hub Password/Token',
    entropyThreshold: 3.0,
    contextKeywords: ['docker', 'password', 'token'],
    exampleMatch: 'docker_password: dckr_pat_abc123...'
  },

  // Cloudflare API Keys (more targeted)
  {
    type: 'CLOUDFLARE_KEY',
    pattern: /(?:cloudflare|CF)[_-]?(?:API)?[_-]?(?:KEY|TOKEN)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_-]{37,})/gi,
    description: 'Cloudflare API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['cloudflare', 'api', 'key'],
    exampleMatch: 'CF_API_KEY=c1234567890abcdef...'
  },

  // Shopify Keys
  {
    type: 'SHOPIFY_KEY',
    pattern: /(?<![A-Za-z0-9])shp[ps]t_[a-fA-F0-9]{32}(?![A-Za-z0-9])/g,
    description: 'Shopify Private/Public App Token',
    entropyThreshold: 3.0,
    contextKeywords: ['shopify', 'token', 'api'],
    exampleMatch: 'shpat_1234567890abcdef1234567890ab'
  },

  // GitLab Personal Access Tokens
  {
    type: 'GITLAB_TOKEN',
    pattern: /(?<![A-Za-z0-9])glpat-[a-zA-Z0-9\-_]{20}(?![A-Za-z0-9])/g,
    description: 'GitLab Personal Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['gitlab', 'token', 'pat'],
    exampleMatch: 'glpat-1234567890abcdefghij'
  },

  // Bitbucket App Passwords
  {
    type: 'BITBUCKET_TOKEN',
    pattern: /(?:bitbucket[_-]?app[_-]?password|BITBUCKET[_-]?APP[_-]?PASSWORD)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9]{16,})/gi,
    description: 'Bitbucket App Password',
    entropyThreshold: 3.0,
    contextKeywords: ['bitbucket', 'app', 'password'],
    exampleMatch: 'bitbucket_app_password: ATBBabc123...'
  },

  // PGP Private Keys
  {
    type: 'PGP_KEY',
    pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    description: 'PGP Private Key',
    entropyThreshold: 3.0,
    contextKeywords: ['pgp', 'private', 'key', 'gpg'],
    exampleMatch: '-----BEGIN PGP PRIVATE KEY BLOCK-----'
  },

  // Connection Strings
  {
    type: 'CONNECTION_STRING',
    pattern: /(?:Server|Data Source|Host)=[^;]+;(?:Database|Initial Catalog)=[^;]+;(?:User Id|UID|User)=[^;]+;(?:Password|PWD)=[^;]+/gi,
    description: 'Database Connection String',
    entropyThreshold: 3.0,
    contextKeywords: ['connection', 'server', 'database'],
    exampleMatch: 'Server=localhost;Database=mydb;User=admin;Password=secret;'
  },

  // Terraform Cloud/Enterprise Tokens
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9-_]{60,}(?![A-Za-z0-9])/g,
    description: 'Terraform Cloud/Enterprise API Token',
    entropyThreshold: 4.5,
    contextKeywords: ['terraform', 'atlas', 'token'],
    exampleMatch: 'abc123.atlasv1.xxxx...'
  },

  // Alibaba Cloud AccessKey
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])(?:LTAI)[a-zA-Z0-9]{12,20}(?![A-Za-z0-9])/g,
    description: 'Alibaba Cloud AccessKey ID',
    entropyThreshold: 4.0,
    contextKeywords: ['alibaba', 'aliyun', 'access'],
    exampleMatch: 'LTAI4Fxxxxxxxxxx'
  },

  // DigitalOcean Personal Access Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dop_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g,
    description: 'DigitalOcean Personal Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['digitalocean', 'do', 'token'],
    exampleMatch: 'dop_v1_abc123...'
  },

  // Discord Bot/Webhook Tokens
  {
    type: 'API_KEY',
    pattern: /(?:discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+|[MN][A-Za-z\d]{23}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27})/g,
    description: 'Discord Bot Token or Webhook',
    entropyThreshold: 3.5,
    contextKeywords: ['discord', 'bot', 'webhook'],
    exampleMatch: 'discord.com/api/webhooks/123456789/xxx...'
  },

  // Telegram Bot Token
  {
    type: 'API_KEY',
    pattern: /\d{8,10}:[A-Za-z0-9_-]{35}/g,
    description: 'Telegram Bot Token',
    entropyThreshold: 3.5,
    contextKeywords: ['telegram', 'bot', 'token'],
    exampleMatch: '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'
  },

  // Jira API Token
  {
    type: 'API_KEY',
    pattern: /(?:jira[_-]?api[_-]?token|JIRA[_-]?API[_-]?TOKEN)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9]{24,})/gi,
    description: 'Jira API Token',
    entropyThreshold: 3.0,
    contextKeywords: ['jira', 'atlassian', 'token'],
    exampleMatch: 'jira_api_token: abc123...'
  },

  // OpenAI API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sk-[a-zA-Z0-9]{48}(?![A-Za-z0-9])/g,
    description: 'OpenAI API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['openai', 'chatgpt', 'api'],
    exampleMatch: 'sk-abc123...'
  },

  // Anthropic API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sk-ant-api03-[a-zA-Z0-9-_]{95}(?![A-Za-z0-9])/g,
    description: 'Anthropic API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['anthropic', 'claude', 'api'],
    exampleMatch: 'sk-ant-api03-...'
  },

  // Hugging Face Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])hf_[a-zA-Z0-9]{32,}(?![A-Za-z0-9])/g,
    description: 'Hugging Face Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['huggingface', 'hf', 'token'],
    exampleMatch: 'hf_abc123...'
  },

  // New Relic API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])(?:NRAK|NRAA|NRII)-[A-Za-z0-9_-]{27,}(?![A-Za-z0-9])/g,
    description: 'New Relic API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['newrelic', 'api', 'monitoring'],
    exampleMatch: 'NRAK-abc123...'
  },

  // PlanetScale Password
  {
    type: 'PASSWORD',
    pattern: /(?<![A-Za-z0-9])pscale_pw_[a-zA-Z0-9_-]{43}(?![A-Za-z0-9])/g,
    description: 'PlanetScale Database Password',
    entropyThreshold: 3.0,
    contextKeywords: ['planetscale', 'password', 'database'],
    exampleMatch: 'pscale_pw_abc123...'
  },

  // LaunchDarkly SDK Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?![A-Za-z0-9])/g,
    description: 'LaunchDarkly SDK Key',
    entropyThreshold: 3.0,
    contextKeywords: ['launchdarkly', 'sdk', 'feature'],
    exampleMatch: 'sdk-12345678-1234-1234-1234-123456789012'
  },

  // Salesforce Access Token
  {
    type: 'API_KEY',
    pattern: /(?:00D[a-zA-Z0-9]{12,15}!.{32,})/g,
    description: 'Salesforce Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['salesforce', 'access', 'token'],
    exampleMatch: '00Dxx0000000001!ARsAQ...'
  },

  // Vercel Deploy Token
  {
    type: 'API_KEY',
    pattern: /(?:vercel[_-]?token|VERCEL[_-]?TOKEN)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9]{24,})/gi,
    description: 'Vercel Deploy Token',
    entropyThreshold: 3.0,
    contextKeywords: ['vercel', 'deploy', 'token'],
    exampleMatch: 'vercel_token: abc123...'
  },

  // Netlify Access Token
  {
    type: 'API_KEY',
    pattern: /(?:netlify[_-]?(?:access[_-]?)?token|NETLIFY[_-]?(?:ACCESS[_-]?)?TOKEN)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_-]{40,})/gi,
    description: 'Netlify Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['netlify', 'access', 'token'],
    exampleMatch: 'netlify_access_token: abc123...'
  },

  // --- NEW PATTERNS FROM DEEP ANALYSIS (14 tools + 3 dork files) ---

  // GitHub Fine-Grained Personal Access Token (new format, TruffleHog/SecretScanner)
  {
    type: 'GITHUB_TOKEN',
    pattern: /(?<![A-Za-z0-9])github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}(?![A-Za-z0-9])/g,
    description: 'GitHub Fine-Grained Personal Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['github', 'token', 'pat'],
    exampleMatch: 'github_pat_11ABCDE...'
  },

  // Facebook Access Token (SecretFinder/shhgit/TruffleHog/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])EAACEdEose0cBA[0-9A-Za-z]+(?![A-Za-z0-9])/g,
    description: 'Facebook Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['facebook', 'fb', 'meta', 'token'],
    exampleMatch: 'EAACEdEose0cBAABCDEF...'
  },

  // Google OAuth Access Token (SecretFinder/shhgit/detect-secrets/TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])ya29\.[0-9A-Za-z\-_]+(?![A-Za-z0-9])/g,
    description: 'Google OAuth Access Token',
    entropyThreshold: 3.5,
    contextKeywords: ['google', 'oauth', 'access', 'token'],
    exampleMatch: 'ya29.a0AfH6SMBx...'
  },

  // Google OAuth Client ID (shhgit/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    description: 'Google OAuth Client ID',
    entropyThreshold: 3.0,
    contextKeywords: ['google', 'oauth', 'client', 'gcp'],
    exampleMatch: '123456789-abc123.apps.googleusercontent.com'
  },

  // Google reCAPTCHA Key (SecretFinder)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])6L[0-9A-Za-z\-_]{38}(?![A-Za-z0-9])/g,
    description: 'Google reCAPTCHA Site Key',
    entropyThreshold: 3.5,
    contextKeywords: ['recaptcha', 'captcha', 'google', 'site_key'],
    exampleMatch: '6LdA123456789abcdefghijklmnopqrstuvwxyz'
  },

  // Firebase Cloud Messaging Server Key (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}(?![A-Za-z0-9])/g,
    description: 'Firebase Cloud Messaging Server Key',
    entropyThreshold: 3.5,
    contextKeywords: ['firebase', 'fcm', 'messaging', 'push'],
    exampleMatch: 'AAAAabc1234:APA91b...'
  },

  // Amazon MWS Auth Token (SecretFinder/shhgit)
  {
    type: 'AWS_SECRET_KEY',
    pattern: /(?<![A-Za-z0-9])amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9])/g,
    description: 'Amazon MWS Auth Token',
    entropyThreshold: 3.5,
    contextKeywords: ['amazon', 'mws', 'marketplace'],
    exampleMatch: 'amzn.mws.12345678-1234-1234-1234-123456789012'
  },

  // Mailgun API Key (SecretFinder/shhgit/TruffleHog/detect-secrets)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])key-[0-9a-zA-Z]{32}(?![A-Za-z0-9])/g,
    description: 'Mailgun API Key',
    entropyThreshold: 4.0,
    contextKeywords: ['mailgun', 'email', 'api', 'mail'],
    exampleMatch: 'key-1234567890abcdef1234567890abcdef'
  },

  // Twilio Account SID (SecretFinder/SecretScanner/TruffleHog)
  {
    type: 'TWILIO_KEY',
    pattern: /(?<![A-Za-z0-9])AC[a-zA-Z0-9_\-]{32}(?![A-Za-z0-9])/g,
    description: 'Twilio Account SID',
    entropyThreshold: 3.5,
    contextKeywords: ['twilio', 'account', 'sid', 'sms'],
    exampleMatch: 'AC1234567890abcdef1234567890abcdef'
  },

  // Twilio App SID (SecretFinder)
  {
    type: 'TWILIO_KEY',
    pattern: /(?<![A-Za-z0-9])AP[a-zA-Z0-9_\-]{32}(?![A-Za-z0-9])/g,
    description: 'Twilio App SID',
    entropyThreshold: 3.5,
    contextKeywords: ['twilio', 'app', 'sid'],
    exampleMatch: 'AP1234567890abcdef1234567890abcdef'
  },

  // PyPI API Token (detect-secrets/TruffleHog/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{50,}(?![A-Za-z0-9])/g,
    description: 'PyPI API Token',
    entropyThreshold: 4.5,
    contextKeywords: ['pypi', 'python', 'pip', 'package'],
    exampleMatch: 'pypi-AgEIcHlwaS5vcmc...'
  },

  // HashiCorp Vault Token (TruffleHog/SecretScanner/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])hvs\.[a-zA-Z0-9_-]{24,}(?![A-Za-z0-9])/g,
    description: 'HashiCorp Vault Service Token',
    entropyThreshold: 4.0,
    contextKeywords: ['vault', 'hashicorp', 'secret', 'token'],
    exampleMatch: 'hvs.CAESIJM...'
  },

  // HashiCorp Vault Batch Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])hvb\.[a-zA-Z0-9_-]{24,}(?![A-Za-z0-9])/g,
    description: 'HashiCorp Vault Batch Token',
    entropyThreshold: 4.0,
    contextKeywords: ['vault', 'hashicorp', 'batch', 'token'],
    exampleMatch: 'hvb.AAAAAQabc...'
  },

  // Stripe Restricted API Key (SecretFinder/shhgit/TruffleHog)
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])rk_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])/g,
    description: 'Stripe Restricted API Key',
    entropyThreshold: 4.0,
    contextKeywords: ['stripe', 'restricted', 'api', 'payment'],
    exampleMatch: 'rk_live_abcdefghijklmnopqrstuvwx'
  },

  // Stripe Test Secret Key (TruffleHog/Keyleaksecret — indicates test env)
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])sk_test_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])/g,
    description: 'Stripe Test API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['stripe', 'test', 'api'],
    exampleMatch: 'sk_test_abcdefghijklmnopqrstuvwx'
  },

  // Stripe Webhook Signing Secret (TruffleHog)
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])whsec_[0-9a-zA-Z]{32,}(?![A-Za-z0-9])/g,
    description: 'Stripe Webhook Signing Secret',
    entropyThreshold: 4.0,
    contextKeywords: ['stripe', 'webhook', 'signing', 'secret'],
    exampleMatch: 'whsec_abc123...'
  },

  // Basic Auth in URLs (detect-secrets/shhgit/SecretScanner)
  {
    type: 'GENERIC_SECRET',
    pattern: /(?:https?|ftp):\/\/[^\s\/:@]+:[^\s\/@]+@[^\s\/]+/g,
    description: 'Basic Authentication in URL',
    entropyThreshold: 0,
    contextKeywords: ['url', 'auth', 'basic', 'http'],
    exampleMatch: 'https://user:password@host.com'
  },

  // Artifactory Token (detect-secrets)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])AKC[a-zA-Z0-9]{10,}(?![A-Za-z0-9])/g,
    description: 'JFrog Artifactory API Key',
    entropyThreshold: 4.0,
    contextKeywords: ['artifactory', 'jfrog', 'token', 'registry'],
    exampleMatch: 'AKCp5dLBeRziC...'
  },

  // Azure Storage AccountKey (detect-secrets — more specific than generic Azure)
  {
    type: 'AZURE_KEY',
    pattern: /AccountKey=[a-zA-Z0-9+\/=]{88}/g,
    description: 'Azure Storage Account Key',
    entropyThreshold: 3.0,
    contextKeywords: ['azure', 'storage', 'accountkey', 'blob'],
    exampleMatch: 'AccountKey=abc123...=='
  },

  // Grafana Service Account Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])glsa_[a-zA-Z0-9_+\/=-]{32,}(?![A-Za-z0-9])/g,
    description: 'Grafana Service Account Token',
    entropyThreshold: 3.0,
    contextKeywords: ['grafana', 'dashboard', 'monitoring', 'api'],
    exampleMatch: 'glsa_abc123...'
  },

  // Grafana Cloud API Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])glc_[a-zA-Z0-9_+\/=-]{32,}(?![A-Za-z0-9])/g,
    description: 'Grafana Cloud API Token',
    entropyThreshold: 3.0,
    contextKeywords: ['grafana', 'cloud', 'api', 'monitoring'],
    exampleMatch: 'glc_abc123...'
  },

  // Postman API Key (distinctive prefix)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])PMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9])/g,
    description: 'Postman API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['postman', 'api', 'collection'],
    exampleMatch: 'PMAK-1234567890abcdef12345678-1234567890abcdef1234567890abcdef12'
  },

  // Doppler Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dp\.(?:pt|st)\.[a-zA-Z0-9_-]{43,}(?![A-Za-z0-9])/g,
    description: 'Doppler API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['doppler', 'secret', 'token', 'env'],
    exampleMatch: 'dp.pt.abc123...'
  },

  // Linear API Key (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])lin_api_[a-zA-Z0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Linear API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['linear', 'api', 'project'],
    exampleMatch: 'lin_api_abc123...'
  },

  // Age Encryption Secret Key (TruffleHog)
  {
    type: 'PRIVATE_KEY',
    pattern: /(?<![A-Za-z0-9])AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Za-z0-9])/g,
    description: 'Age Encryption Secret Key',
    entropyThreshold: 4.5,
    contextKeywords: ['age', 'encryption', 'key', 'secret'],
    exampleMatch: 'AGE-SECRET-KEY-1QPZRY...'
  },

  // Discord Webhook URL (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    description: 'Discord Webhook URL',
    entropyThreshold: 3.0,
    contextKeywords: ['discord', 'webhook', 'bot'],
    exampleMatch: 'https://discord.com/api/webhooks/123456789/abc...'
  },

  // Sentry Auth Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sntrys_[a-zA-Z0-9]{40,}(?![A-Za-z0-9])/g,
    description: 'Sentry Auth Token',
    entropyThreshold: 3.5,
    contextKeywords: ['sentry', 'error', 'monitoring'],
    exampleMatch: 'sntrys_abc123...'
  },

  // Sentry DSN (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/g,
    description: 'Sentry DSN',
    entropyThreshold: 3.0,
    contextKeywords: ['sentry', 'dsn', 'error'],
    exampleMatch: 'https://abc123@o123.ingest.sentry.io/456'
  },

  // Notion Integration Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])secret_[a-zA-Z0-9]{43}(?![A-Za-z0-9])/g,
    description: 'Notion Integration Token',
    entropyThreshold: 3.0,
    contextKeywords: ['notion', 'integration', 'secret'],
    exampleMatch: 'secret_abc123...'
  },

  // Contentful Management Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])CFPAT-[a-zA-Z0-9_-]{43}(?![A-Za-z0-9])/g,
    description: 'Contentful Management API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['contentful', 'cms', 'management'],
    exampleMatch: 'CFPAT-abc123...'
  },

  // Dynatrace API Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}(?![A-Za-z0-9])/g,
    description: 'Dynatrace API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['dynatrace', 'monitoring', 'apm'],
    exampleMatch: 'dt0c01.ABC123...'
  },

  // Sendinblue/Brevo API Key (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}(?![A-Za-z0-9])/g,
    description: 'Sendinblue/Brevo API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['sendinblue', 'brevo', 'email', 'api'],
    exampleMatch: 'xkeysib-abc123...-XYZ123'
  },

  // Dropbox Access Token (TruffleHog/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sl\.[A-Za-z0-9_-]{100,}(?![A-Za-z0-9])/g,
    description: 'Dropbox Access Token',
    entropyThreshold: 3.5,
    contextKeywords: ['dropbox', 'access', 'token', 'storage'],
    exampleMatch: 'sl.abc123...'
  },

  // Fly.io API Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])fo1_[a-zA-Z0-9_-]{39}(?![A-Za-z0-9])/g,
    description: 'Fly.io API Token',
    entropyThreshold: 3.0,
    contextKeywords: ['fly', 'flyio', 'deploy', 'token'],
    exampleMatch: 'fo1_abc123...'
  },

  // Render API Key (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])rnd_[a-zA-Z0-9]{32,}(?![A-Za-z0-9])/g,
    description: 'Render API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['render', 'deploy', 'api'],
    exampleMatch: 'rnd_abc123...'
  },

  // SonarQube/SonarCloud Token (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sqp_[a-f0-9]{40}(?![A-Za-z0-9])/g,
    description: 'SonarQube/SonarCloud Token',
    entropyThreshold: 3.0,
    contextKeywords: ['sonar', 'sonarqube', 'code', 'quality'],
    exampleMatch: 'sqp_abc123...'
  },

  // NuGet API Key (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])oy2[a-z0-9]{43}(?![A-Za-z0-9])/g,
    description: 'NuGet API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['nuget', 'dotnet', 'package'],
    exampleMatch: 'oy2abc123...'
  },

  // RubyGems API Key (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])rubygems_[a-f0-9]{48}(?![A-Za-z0-9])/g,
    description: 'RubyGems API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['rubygems', 'gem', 'ruby'],
    exampleMatch: 'rubygems_abc123...'
  },

  // Docker Hub Personal Access Token (TruffleHog)
  {
    type: 'DOCKER_PASSWORD',
    pattern: /(?<![A-Za-z0-9])dckr_pat_[a-zA-Z0-9_-]+(?![A-Za-z0-9])/g,
    description: 'Docker Hub Personal Access Token',
    entropyThreshold: 3.5,
    contextKeywords: ['docker', 'hub', 'registry', 'pat'],
    exampleMatch: 'dckr_pat_abc123...'
  },

  // Pulumi Access Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])pul-[a-f0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Pulumi Access Token',
    entropyThreshold: 4.0,
    contextKeywords: ['pulumi', 'infrastructure', 'iac'],
    exampleMatch: 'pul-abc123...'
  },

  // Replicate API Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])r8_[a-zA-Z0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Replicate API Token',
    entropyThreshold: 4.0,
    contextKeywords: ['replicate', 'ai', 'ml', 'model'],
    exampleMatch: 'r8_abc123...'
  },

  // Figma Personal Access Token (TruffleHog)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])figd_[a-zA-Z0-9_-]{40,}(?![A-Za-z0-9])/g,
    description: 'Figma Personal Access Token',
    entropyThreshold: 4.0,
    contextKeywords: ['figma', 'design', 'token'],
    exampleMatch: 'figd_abc123...'
  },

  // Databricks API Token (Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dapi[a-h0-9]{32}(?![A-Za-z0-9])/g,
    description: 'Databricks API Token',
    entropyThreshold: 4.0,
    contextKeywords: ['databricks', 'spark', 'data'],
    exampleMatch: 'dapiabc123...'
  },

  // Firebase Database URL (TruffleHog/SecretScanner)
  {
    type: 'API_KEY',
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g,
    description: 'Firebase Realtime Database URL',
    entropyThreshold: 0,
    contextKeywords: ['firebase', 'database', 'realtime'],
    exampleMatch: 'https://my-app.firebaseio.com'
  },

  // GitLab extended tokens: Pipeline Trigger, Runner Registration (TruffleHog)
  {
    type: 'GITLAB_TOKEN',
    pattern: /(?<![A-Za-z0-9])(?:glptt-[0-9a-f]{40}|GR1348941[0-9a-zA-Z\-_]{20,})(?![A-Za-z0-9])/g,
    description: 'GitLab Pipeline Trigger or Runner Registration Token',
    entropyThreshold: 4.0,
    contextKeywords: ['gitlab', 'pipeline', 'runner', 'ci'],
    exampleMatch: 'glptt-abc123...'
  },

  // --- ADDITIONAL PATTERNS FROM SECRETFINDER.PY DEEP REVIEW ---

  // HTTP Basic Auth header value (SecretFinder `authorization_basic`)
  // Matches hardcoded "Authorization: basic BASE64VALUE" in source code
  {
    type: 'GENERIC_SECRET',
    pattern: /(?:authorization|auth)['\"\s]*[:=]['\"\s]*basic\s+[a-zA-Z0-9+/]{10,}={0,2}/gi,
    description: 'HTTP Basic Auth Header Value',
    entropyThreshold: 3.0,
    contextKeywords: ['authorization', 'auth', 'basic', 'header'],
    exampleMatch: 'Authorization: basic dXNlcjpwYXNzd29yZA=='
  },

  // Embedded credentials in GitHub clone/push URLs (SecretFinder `github_access_token`)
  // Catches: https://username:token@github.com/org/repo
  {
    type: 'GITHUB_TOKEN',
    pattern: /[a-zA-Z0-9_-]+:[a-zA-Z0-9_\-]{8,}@github\.com/g,
    description: 'Embedded GitHub Credentials in URL',
    entropyThreshold: 3.5,
    contextKeywords: ['github', 'git', 'clone', 'remote', 'url'],
    exampleMatch: 'https://user:ghp_TOKEN@github.com/org/repo'
  },

  // Square Extended Access Token — EAAA format (SecretFinder `square_access_token`)
  {
    type: 'SQUARE_KEY',
    pattern: /(?<![A-Za-z0-9])EAAA[a-zA-Z0-9]{60}(?![A-Za-z0-9])/g,
    description: 'Square Extended Access Token',
    entropyThreshold: 4.0,
    contextKeywords: ['square', 'payment', 'token'],
    exampleMatch: 'EAAAEABCDEFabcdef1234567890...'
  },

  // --- ADDITIONAL PATTERNS FROM Github_Dorks_TO_APPLY ---

  // Neo4j Connection String (bolt or neo4j protocol)
  {
    type: 'DATABASE_URL',
    pattern: /neo4j(?:\+s(?:sc)?)?:\/\/[^\s\'"<>]+/gi,
    description: 'Neo4j Database Connection String',
    entropyThreshold: 3.0,
    contextKeywords: ['neo4j', 'graph', 'database', 'bolt'],
    exampleMatch: 'neo4j+s://user:password@host:7687/db'
  },

  // Pulumi Access Token — extended format (pulumip- prefix)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])pulumip-[a-zA-Z0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Pulumi Access Token (extended format)',
    entropyThreshold: 4.0,
    contextKeywords: ['pulumi', 'infrastructure', 'iac'],
    exampleMatch: 'pulumip-abc123...'
  },

  // 1Password Service Account Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])ops_eyJ[A-Za-z0-9_-]+(?![A-Za-z0-9])/g,
    description: '1Password Service Account Token',
    entropyThreshold: 4.0,
    contextKeywords: ['1password', 'onepassword', 'vault', 'secret'],
    exampleMatch: 'ops_eyJhbGciOiJFUzI1NiIs...'
  },

  // Cloudinary URL (contains API key and secret)
  {
    type: 'GENERIC_SECRET',
    pattern: /cloudinary:\/\/[^\s\'"<>]+/gi,
    description: 'Cloudinary URL with embedded credentials',
    entropyThreshold: 3.0,
    contextKeywords: ['cloudinary', 'cloud_name', 'image', 'upload'],
    exampleMatch: 'cloudinary://api_key:api_secret@cloud_name'
  },

  // SQL Server Connection String (sqlserver:// protocol)
  {
    type: 'DATABASE_URL',
    pattern: /sqlserver:\/\/[^\s\'"<>]+/gi,
    description: 'SQL Server Connection String',
    entropyThreshold: 3.0,
    contextKeywords: ['sqlserver', 'mssql', 'database'],
    exampleMatch: 'sqlserver://user:password@host:1433/database'
  },

  // --- NEW PATTERNS FOR GITHUB-DORKS ---

  // NPM Registry Auth Token (from .npmrc _auth)
  {
    type: 'NPMRC_AUTH',
    pattern: /(?:_auth\s*=\s*)([A-Za-z0-9+/=]{40,})/g,
    description: 'NPM Registry Auth Token (Base64)',
    entropyThreshold: 4.0,
    contextKeywords: ['npm', 'auth', 'registry', 'npmrc'],
    exampleMatch: '_auth = dXNlcjpwYXNzd29yZA=='
  }
];

/**
 * Build domain-specific patterns
 */
export function getDomainPatterns(domain: string): SecretPattern[] {
  const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  return [
    {
      type: 'EMAIL',
      pattern: new RegExp(`[a-zA-Z0-9._%+-]+@${escapedDomain}`, 'gi'),
      description: `Email addresses with ${domain}`,
      entropyThreshold: 0,
      contextKeywords: ['email', 'mail', 'contact']
    }
  ];
}

/**
 * Calculate Shannon entropy of a string
 * Higher entropy suggests more randomness (likely a real secret)
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if content contains context keywords
 */
export function hasContextKeywords(content: string, keywords: string[]): boolean {
  if (!keywords || keywords.length === 0) return false;

  const lowerContent = content.toLowerCase();
  return keywords.some(keyword => lowerContent.includes(keyword.toLowerCase()));
}

/**
 * Extract context around a match (5 lines before and after)
 */
export function extractContext(content: string, matchIndex: number, contextLines: number = 5): string {
  const lines = content.split('\n');
  let currentPos = 0;
  let matchLine = 0;

  for (let i = 0; i < lines.length; i++) {
    if (currentPos + lines[i].length >= matchIndex) {
      matchLine = i;
      break;
    }
    currentPos += lines[i].length + 1;
  }

  const startLine = Math.max(0, matchLine - contextLines);
  const endLine = Math.min(lines.length, matchLine + contextLines + 1);

  return lines.slice(startLine, endLine).join('\n');
}

/**
 * Create content preview (first 10 and last 10 chars)
 */
export function createPreview(content: string): string {
  if (content.length <= 20) {
    return content.substring(0, 4) + '***' + content.substring(content.length - 4);
  }
  return content.substring(0, 10) + '...' + content.substring(content.length - 10);
}

/**
 * Common false positive patterns to exclude
 * Refined: "test" only matches as part of test_key/test_token patterns,
 * NOT as generic substring (avoids filtering real secrets in test environments)
 */
const FALSE_POSITIVE_PATTERNS = [
  /\bexample\b/i,
  /\bsample\b/i,
  /\bdemo\b/i,
  /\bplaceholder\b/i,
  /\bdummy\b/i,
  /\bfake\b/i,
  /your[_-]?.*here/i,
  /change[_-]?me/i,
  /replace[_-]?this/i,
  /\*{3,}/,        // Multiple asterisks
  /x{6,}/i,        // 6+ x's (relaxed from 3)
  /\.{5,}/,        // 5+ dots (relaxed from 3)
  /^(example|sample|demo|placeholder|dummy|fake)$/i,
  /\btest[_-]?(?:key|token|secret|password|api[_-]?key)\b/i,
  /\b(?:key|token|secret|password)_?test\b/i,
  /TODO|FIXME|CHANGEME/i
];

/**
 * Check if match is likely a false positive
 * More conservative: only checks the match itself and explicit context indicators
 */
export function isFalsePositive(match: string, context: string): boolean {
  // Check the match content itself
  if (FALSE_POSITIVE_PATTERNS.some(pattern => pattern.test(match))) {
    return true;
  }

  // Only check context for very explicit false positive indicators
  const contextLower = context.toLowerCase();
  if (
    contextLower.includes('placeholder') ||
    contextLower.includes('example.com') ||
    contextLower.includes('dummy') ||
    contextLower.includes('changeme') ||
    contextLower.includes('your_key_here') ||
    contextLower.includes('replace_this')
  ) {
    return true;
  }

  return false;
}
