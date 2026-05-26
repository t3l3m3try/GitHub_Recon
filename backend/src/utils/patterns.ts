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
    entropyThreshold: 3.8,
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

  // GitHub Fine-Grained Personal Access Token (new format, SecretScanner)
  {
    type: 'GITHUB_TOKEN',
    pattern: /(?<![A-Za-z0-9])github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}(?![A-Za-z0-9])/g,
    description: 'GitHub Fine-Grained Personal Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['github', 'token', 'pat'],
    exampleMatch: 'github_pat_11ABCDE...'
  },

  // Facebook Access Token (SecretFinder/shhgit/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])EAACEdEose0cBA[0-9A-Za-z]+(?![A-Za-z0-9])/g,
    description: 'Facebook Access Token',
    entropyThreshold: 3.0,
    contextKeywords: ['facebook', 'fb', 'meta', 'token'],
    exampleMatch: 'EAACEdEose0cBAABCDEF...'
  },

  // Google OAuth Access Token (SecretFinder/shhgit/detect-secrets)
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

  // Firebase Cloud Messaging Server Key (SecretScanner)
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

  // Mailgun API Key (SecretFinder/shhgit/detect-secrets)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])key-[0-9a-zA-Z]{32}(?![A-Za-z0-9])/g,
    description: 'Mailgun API Key',
    entropyThreshold: 4.0,
    contextKeywords: ['mailgun', 'email', 'api', 'mail'],
    exampleMatch: 'key-1234567890abcdef1234567890abcdef'
  },

  // Twilio Account SID (SecretFinder/SecretScanner)
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

  // PyPI API Token (detect-secrets/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{50,}(?![A-Za-z0-9])/g,
    description: 'PyPI API Token',
    entropyThreshold: 4.5,
    contextKeywords: ['pypi', 'python', 'pip', 'package'],
    exampleMatch: 'pypi-AgEIcHlwaS5vcmc...'
  },

  // HashiCorp Vault Token (SecretScanner/Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])hvs\.[a-zA-Z0-9_-]{24,}(?![A-Za-z0-9])/g,
    description: 'HashiCorp Vault Service Token',
    entropyThreshold: 4.0,
    contextKeywords: ['vault', 'hashicorp', 'secret', 'token'],
    exampleMatch: 'hvs.CAESIJM...'
  },

  // HashiCorp Vault Batch Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])hvb\.[a-zA-Z0-9_-]{24,}(?![A-Za-z0-9])/g,
    description: 'HashiCorp Vault Batch Token',
    entropyThreshold: 4.0,
    contextKeywords: ['vault', 'hashicorp', 'batch', 'token'],
    exampleMatch: 'hvb.AAAAAQabc...'
  },

  // Stripe Restricted API Key (SecretFinder/shhgit)
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])rk_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])/g,
    description: 'Stripe Restricted API Key',
    entropyThreshold: 4.0,
    contextKeywords: ['stripe', 'restricted', 'api', 'payment'],
    exampleMatch: 'rk_live_abcdefghijklmnopqrstuvwx'
  },

  // Stripe Test Secret Key (Keyleaksecret — indicates test env)
  {
    type: 'STRIPE_KEY',
    pattern: /(?<![A-Za-z0-9])sk_test_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])/g,
    description: 'Stripe Test API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['stripe', 'test', 'api'],
    exampleMatch: 'sk_test_abcdefghijklmnopqrstuvwx'
  },

  // Stripe Webhook Signing Secret
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

  // Grafana Service Account Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])glsa_[a-zA-Z0-9_+\/=-]{32,}(?![A-Za-z0-9])/g,
    description: 'Grafana Service Account Token',
    entropyThreshold: 3.0,
    contextKeywords: ['grafana', 'dashboard', 'monitoring', 'api'],
    exampleMatch: 'glsa_abc123...'
  },

  // Grafana Cloud API Token
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

  // Doppler Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dp\.(?:pt|st)\.[a-zA-Z0-9_-]{43,}(?![A-Za-z0-9])/g,
    description: 'Doppler API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['doppler', 'secret', 'token', 'env'],
    exampleMatch: 'dp.pt.abc123...'
  },

  // Linear API Key (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])lin_api_[a-zA-Z0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Linear API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['linear', 'api', 'project'],
    exampleMatch: 'lin_api_abc123...'
  },

  // Age Encryption Secret Key
  {
    type: 'PRIVATE_KEY',
    pattern: /(?<![A-Za-z0-9])AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Za-z0-9])/g,
    description: 'Age Encryption Secret Key',
    entropyThreshold: 4.5,
    contextKeywords: ['age', 'encryption', 'key', 'secret'],
    exampleMatch: 'AGE-SECRET-KEY-1QPZRY...'
  },

  // Discord Webhook URL (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    description: 'Discord Webhook URL',
    entropyThreshold: 3.0,
    contextKeywords: ['discord', 'webhook', 'bot'],
    exampleMatch: 'https://discord.com/api/webhooks/123456789/abc...'
  },

  // Sentry Auth Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sntrys_[a-zA-Z0-9]{40,}(?![A-Za-z0-9])/g,
    description: 'Sentry Auth Token',
    entropyThreshold: 3.5,
    contextKeywords: ['sentry', 'error', 'monitoring'],
    exampleMatch: 'sntrys_abc123...'
  },

  // Sentry DSN
  {
    type: 'API_KEY',
    pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/g,
    description: 'Sentry DSN',
    entropyThreshold: 3.0,
    contextKeywords: ['sentry', 'dsn', 'error'],
    exampleMatch: 'https://abc123@o123.ingest.sentry.io/456'
  },

  // Notion Integration Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])secret_[a-zA-Z0-9]{43}(?![A-Za-z0-9])/g,
    description: 'Notion Integration Token',
    entropyThreshold: 3.0,
    contextKeywords: ['notion', 'integration', 'secret'],
    exampleMatch: 'secret_abc123...'
  },

  // Contentful Management Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])CFPAT-[a-zA-Z0-9_-]{43}(?![A-Za-z0-9])/g,
    description: 'Contentful Management API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['contentful', 'cms', 'management'],
    exampleMatch: 'CFPAT-abc123...'
  },

  // Dynatrace API Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}(?![A-Za-z0-9])/g,
    description: 'Dynatrace API Token',
    entropyThreshold: 3.5,
    contextKeywords: ['dynatrace', 'monitoring', 'apm'],
    exampleMatch: 'dt0c01.ABC123...'
  },

  // Sendinblue/Brevo API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}(?![A-Za-z0-9])/g,
    description: 'Sendinblue/Brevo API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['sendinblue', 'brevo', 'email', 'api'],
    exampleMatch: 'xkeysib-abc123...-XYZ123'
  },

  // Dropbox Access Token (Keyleaksecret)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sl\.[A-Za-z0-9_-]{100,}(?![A-Za-z0-9])/g,
    description: 'Dropbox Access Token',
    entropyThreshold: 3.5,
    contextKeywords: ['dropbox', 'access', 'token', 'storage'],
    exampleMatch: 'sl.abc123...'
  },

  // Fly.io API Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])fo1_[a-zA-Z0-9_-]{39}(?![A-Za-z0-9])/g,
    description: 'Fly.io API Token',
    entropyThreshold: 3.0,
    contextKeywords: ['fly', 'flyio', 'deploy', 'token'],
    exampleMatch: 'fo1_abc123...'
  },

  // Render API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])rnd_[a-zA-Z0-9]{32,}(?![A-Za-z0-9])/g,
    description: 'Render API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['render', 'deploy', 'api'],
    exampleMatch: 'rnd_abc123...'
  },

  // SonarQube/SonarCloud Token (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])sqp_[a-f0-9]{40}(?![A-Za-z0-9])/g,
    description: 'SonarQube/SonarCloud Token',
    entropyThreshold: 3.0,
    contextKeywords: ['sonar', 'sonarqube', 'code', 'quality'],
    exampleMatch: 'sqp_abc123...'
  },

  // NuGet API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])oy2[a-z0-9]{43}(?![A-Za-z0-9])/g,
    description: 'NuGet API Key',
    entropyThreshold: 3.0,
    contextKeywords: ['nuget', 'dotnet', 'package'],
    exampleMatch: 'oy2abc123...'
  },

  // RubyGems API Key
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])rubygems_[a-f0-9]{48}(?![A-Za-z0-9])/g,
    description: 'RubyGems API Key',
    entropyThreshold: 3.5,
    contextKeywords: ['rubygems', 'gem', 'ruby'],
    exampleMatch: 'rubygems_abc123...'
  },

  // Docker Hub Personal Access Token
  {
    type: 'DOCKER_PASSWORD',
    pattern: /(?<![A-Za-z0-9])dckr_pat_[a-zA-Z0-9_-]+(?![A-Za-z0-9])/g,
    description: 'Docker Hub Personal Access Token',
    entropyThreshold: 3.5,
    contextKeywords: ['docker', 'hub', 'registry', 'pat'],
    exampleMatch: 'dckr_pat_abc123...'
  },

  // Pulumi Access Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])pul-[a-f0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Pulumi Access Token',
    entropyThreshold: 4.0,
    contextKeywords: ['pulumi', 'infrastructure', 'iac'],
    exampleMatch: 'pul-abc123...'
  },

  // Replicate API Token
  {
    type: 'API_KEY',
    pattern: /(?<![A-Za-z0-9])r8_[a-zA-Z0-9]{40}(?![A-Za-z0-9])/g,
    description: 'Replicate API Token',
    entropyThreshold: 4.0,
    contextKeywords: ['replicate', 'ai', 'ml', 'model'],
    exampleMatch: 'r8_abc123...'
  },

  // Figma Personal Access Token
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

  // Firebase Database URL (SecretScanner)
  {
    type: 'API_KEY',
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g,
    description: 'Firebase Realtime Database URL',
    entropyThreshold: 0,
    contextKeywords: ['firebase', 'database', 'realtime'],
    exampleMatch: 'https://my-app.firebaseio.com'
  },

  // GitLab extended tokens: Pipeline Trigger, Runner Registration
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
  },
  // ==================================================
  // --- BETTERLEAKS 100% COVERAGE RULES ---
  // ==================================================
  // 1Password Secret Key (betterleaks: 1password-secret-key)
  {
    pattern: /\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/g,
    type: '1PASSWORD_SECRET_KEY',
    description: 'Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.',
    contextKeywords: ['a3-'],
  },
  // 1Password Service Account Token (betterleaks: 1password-service-account-token)
  {
    pattern: /ops_eyJ[a-zA-Z0-9+\/]{250,}={0,3}/g,
    type: '1PASSWORD_SERVICE_ACCOUNT_TOKEN',
    description: 'Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.',
    contextKeywords: ['ops_'],
  },
  // Adafruit Api Key (betterleaks: adafruit-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ADAFRUIT_API_KEY',
    description: 'Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.',
    contextKeywords: ['adafruit'],
  },
  // Adobe Client Id (betterleaks: adobe-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:adobe)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ADOBE_CLIENT_ID',
    description: 'Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.',
    contextKeywords: ['adobe'],
  },
  // Adobe Client Secret (betterleaks: adobe-client-secret)
  {
    pattern: /\b(p8e-[a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ADOBE_CLIENT_SECRET',
    description: 'Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.',
    contextKeywords: ['p8e-'],
  },
  // Age Secret Key (betterleaks: age-secret-key)
  {
    pattern: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g,
    type: 'AGE_SECRET_KEY',
    description: 'Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.',
    contextKeywords: ['age-secret-key-1'],
  },
  // Airtable Api Key (betterleaks: airtable-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:airtable)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{17})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'AIRTABLE_API_KEY',
    description: 'Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.',
    contextKeywords: ['airtable'],
  },
  // Airtable Personnal Access Token (betterleaks: airtable-personnal-access-token)
  {
    pattern: /\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b/g,
    type: 'AIRTABLE_PERSONNAL_ACCESS_TOKEN',
    description: 'Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.',
    contextKeywords: ['airtable'],
  },
  // Algolia Api Key (betterleaks: algolia-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ALGOLIA_API_KEY',
    description: 'Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.',
    contextKeywords: ['algolia'],
  },
  // Alibaba Access Key Id (betterleaks: alibaba-access-key-id)
  {
    pattern: /\b(LTAI[a-z0-9]{20})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ALIBABA_ACCESS_KEY_ID',
    description: 'Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.',
    contextKeywords: ['ltai'],
  },
  // Alibaba Secret Key (betterleaks: alibaba-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:alibaba)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{30})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ALIBABA_SECRET_KEY',
    description: 'Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.',
    contextKeywords: ['alibaba'],
  },
  // Anthropic Admin Api Key (betterleaks: anthropic-admin-api-key)
  {
    pattern: /\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'ANTHROPIC_ADMIN_API_KEY',
    description: 'Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.',
    contextKeywords: ['sk-ant-admin01'],
  },
  // Anthropic Api Key (betterleaks: anthropic-api-key)
  {
    pattern: /\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'ANTHROPIC_API_KEY',
    description: 'Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.',
    contextKeywords: ['sk-ant-api03'],
  },
  // Artifactory Api Key (betterleaks: artifactory-api-key)
  {
    pattern: /\bAKCp[A-Za-z0-9]{69}\b/g,
    type: 'ARTIFACTORY_API_KEY',
    description: 'Detected an Artifactory api key, posing a risk unauthorized access to the central repository.',
    contextKeywords: ['akcp'],
  },
  // Artifactory Reference Token (betterleaks: artifactory-reference-token)
  {
    pattern: /\bcmVmd[A-Za-z0-9]{59}\b/g,
    type: 'ARTIFACTORY_REFERENCE_TOKEN',
    description: 'Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.',
    contextKeywords: ['cmvmd'],
  },
  // Asana Client Id (betterleaks: asana-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ASANA_CLIENT_ID',
    description: 'Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.',
    contextKeywords: ['asana'],
  },
  // Asana Client Secret (betterleaks: asana-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ASANA_CLIENT_SECRET',
    description: 'Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.',
    contextKeywords: ['asana'],
  },
  // Assemblyai Api Key (betterleaks: assemblyai-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:assemblyai)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ASSEMBLYAI_API_KEY',
    description: 'Detected an AssemblyAI API Key, which may expose speech-to-text services and associated audio data to unauthorized access.',
    contextKeywords: ['assemblyai'],
  },
  // Atlassian Api Token (betterleaks: atlassian-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)|\b(ATATT3[A-Za-z0-9_\-=]{186})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ATLASSIAN_API_TOKEN',
    description: 'Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.',
    contextKeywords: [],
  },
  // Authress Service Client Access Key (betterleaks: authress-service-client-access-key)
  {
    pattern: /\b((?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+\/_=-]{30,120})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'AUTHRESS_SERVICE_CLIENT_ACCESS_KEY',
    description: 'Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.',
    contextKeywords: [],
  },
  // Aws Access Token (betterleaks: aws-access-token)
  {
    pattern: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g,
    type: 'AWS_ACCESS_TOKEN',
    description: 'Identified an AWS access key ID paired with a secret access key, which together can provide full access to AWS services.',
    contextKeywords: [],
  },
  // Aws Amazon Bedrock Api Key Long Lived (betterleaks: aws-amazon-bedrock-api-key-long-lived)
  {
    pattern: /\b(ABSK[A-Za-z0-9+\/]{109,269}={0,2})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'AWS_AMAZON_BEDROCK_API_KEY_LONG_LIVED',
    description: 'Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage',
    contextKeywords: ['absk'],
  },
  // Aws Amazon Bedrock Api Key Short Lived (betterleaks: aws-amazon-bedrock-api-key-short-lived)
  {
    pattern: /bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t/g,
    type: 'AWS_AMAZON_BEDROCK_API_KEY_SHORT_LIVED',
    description: 'Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage',
    contextKeywords: ['bedrock-api-key-'],
  },
  // Aws Secret Access Key (betterleaks: aws-secret-access-key)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:secret|access|key|token)(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([A-Za-z0-9\/+=]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'AWS_SECRET_ACCESS_KEY',
    description: 'Identified an AWS secret access key, used as a component of the aws-access-token composite rule.',
    contextKeywords: [],
  },
  // Azure Ad Client Secret (betterleaks: azure-ad-client-secret)
  {
    pattern: /(?:^|[\\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\'"\x60\s<),])/g,
    type: 'AZURE_AD_CLIENT_SECRET',
    description: 'Azure AD Client Secret',
    contextKeywords: ['q~'],
  },
  // Beamer Api Token (betterleaks: beamer-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(b_[a-z0-9=_\-]{44})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'BEAMER_API_TOKEN',
    description: 'Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.',
    contextKeywords: ['beamer'],
  },
  // Bitbucket Client Id (betterleaks: bitbucket-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'BITBUCKET_CLIENT_ID',
    description: 'Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.',
    contextKeywords: ['bitbucket'],
  },
  // Bitbucket Client Secret (betterleaks: bitbucket-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'BITBUCKET_CLIENT_SECRET',
    description: 'Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.',
    contextKeywords: ['bitbucket'],
  },
  // Bittrex Access Key (betterleaks: bittrex-access-key)
  {
    pattern: /[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'BITTREX_ACCESS_KEY',
    description: 'Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.',
    contextKeywords: ['bittrex'],
  },
  // Bittrex Secret Key (betterleaks: bittrex-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'BITTREX_SECRET_KEY',
    description: 'Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.',
    contextKeywords: ['bittrex'],
  },
  // Cerebras Api Key (betterleaks: cerebras-api-key)
  {
    pattern: /\b(csk-[a-z0-9]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CEREBRAS_API_KEY',
    description: 'Identified a Cerebras AI API Key, which may expose AI inference services to unauthorized access.',
    contextKeywords: ['csk-'],
  },
  // Cisco Meraki Api Key (betterleaks: cisco-meraki-api-key)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'CISCO_MERAKI_API_KEY',
    description: 'Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.',
    contextKeywords: ['meraki'],
  },
  // Clickhouse Cloud Api Secret Key (betterleaks: clickhouse-cloud-api-secret-key)
  {
    pattern: /\b(4b1d[A-Za-z0-9]{38})\b/g,
    type: 'CLICKHOUSE_CLOUD_API_SECRET_KEY',
    description: 'Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.',
    contextKeywords: ['4b1d'],
  },
  // Clojars Api Token (betterleaks: clojars-api-token)
  {
    pattern: /CLOJARS_[a-z0-9]{60}/gi,
    type: 'CLOJARS_API_TOKEN',
    description: 'Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.',
    contextKeywords: ['clojars_'],
  },
  // Cloudflare Api Key (betterleaks: cloudflare-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CLOUDFLARE_API_KEY',
    description: 'Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.',
    contextKeywords: ['cloudflare'],
  },
  // Cloudflare Global Api Key (betterleaks: cloudflare-global-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{37})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CLOUDFLARE_GLOBAL_API_KEY',
    description: 'Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.',
    contextKeywords: ['cloudflare'],
  },
  // Cloudflare Origin Ca Key (betterleaks: cloudflare-origin-ca-key)
  {
    pattern: /\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'CLOUDFLARE_ORIGIN_CA_KEY',
    description: 'Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.',
    contextKeywords: [],
  },
  // Codecov Access Token (betterleaks: codecov-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:codecov)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CODECOV_ACCESS_TOKEN',
    description: 'Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.',
    contextKeywords: ['codecov'],
  },
  // Cohere Api Token (betterleaks: cohere-api-token)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-zA-Z0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'COHERE_API_TOKEN',
    description: 'Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.',
    contextKeywords: [],
  },
  // Coinbase Access Token (betterleaks: coinbase-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'COINBASE_ACCESS_TOKEN',
    description: 'Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.',
    contextKeywords: ['coinbase'],
  },
  // Confluent Access Token (betterleaks: confluent-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CONFLUENT_ACCESS_TOKEN',
    description: 'Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.',
    contextKeywords: ['confluent'],
  },
  // Confluent Secret Key (betterleaks: confluent-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CONFLUENT_SECRET_KEY',
    description: 'Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.',
    contextKeywords: ['confluent'],
  },
  // Contentful Delivery Api Token (betterleaks: contentful-delivery-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{43})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CONTENTFUL_DELIVERY_API_TOKEN',
    description: 'Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.',
    contextKeywords: ['contentful'],
  },
  // Curl Auth Header (betterleaks: curl-auth-header)
  {
    pattern: /\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+\/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+\/-]{8,})|([\w=~@.+\/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+\/-]{8,}))"|\'(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+\/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+\/-]{8,})|([\w=~@.+\/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+\/-]{8,}))\')(?:\B|\s|\z)/gi,
    type: 'CURL_AUTH_HEADER',
    description: 'Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.',
    contextKeywords: ['curl'],
  },
  // Curl Auth User (betterleaks: curl-auth-user)
  {
    pattern: /\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|\'([^:\']{3,}:[^\']{3,})\'|((?:"[^"]{3,}"|\'[^\']{3,}\'|[\w$@.-]+):(?:"[^"]{3,}"|\'[^\']{3,}\'|[\w${}@.-]+)))(?:\s|\z)/g,
    type: 'CURL_AUTH_USER',
    description: 'Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.',
    contextKeywords: ['curl'],
  },
  // Cursor Api Key (betterleaks: cursor-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:cursor)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(key_[0-9a-f]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'CURSOR_API_KEY',
    description: 'Detected a Cursor Integrations API Key, which may expose AI-assisted development services to unauthorized access.',
    contextKeywords: ['cursor'],
  },
  // Databricks Api Token (betterleaks: databricks-api-token)
  {
    pattern: /\b(dapi[a-f0-9]{32}(?:-\d)?)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'DATABRICKS_API_TOKEN',
    description: 'Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.',
    contextKeywords: ['dapi'],
  },
  // Datadog Access Token (betterleaks: datadog-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DATADOG_ACCESS_TOKEN',
    description: 'Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.',
    contextKeywords: ['datadog'],
  },
  // Deepgram Api Key (betterleaks: deepgram-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:deepgram)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DEEPGRAM_API_KEY',
    description: 'Detected a Deepgram API Key, which may expose speech recognition services and audio data to unauthorized access.',
    contextKeywords: ['deepgram'],
  },
  // Deepseek Api Key (betterleaks: deepseek-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:deepseek)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(sk-[a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DEEPSEEK_API_KEY',
    description: 'Detected a DeepSeek API Key, which may expose AI model access and associated usage to unauthorized parties.',
    contextKeywords: ['deepseek'],
  },
  // Defined Networking Api Token (betterleaks: defined-networking-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DEFINED_NETWORKING_API_TOKEN',
    description: 'Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.',
    contextKeywords: ['dnkey'],
  },
  // Digitalocean Access Token (betterleaks: digitalocean-access-token)
  {
    pattern: /\b(doo_v1_[a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'DIGITALOCEAN_ACCESS_TOKEN',
    description: 'Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.',
    contextKeywords: ['doo_v1_'],
  },
  // Digitalocean Pat (betterleaks: digitalocean-pat)
  {
    pattern: /\b(dop_v1_[a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'DIGITALOCEAN_PAT',
    description: 'Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.',
    contextKeywords: ['dop_v1_'],
  },
  // Digitalocean Refresh Token (betterleaks: digitalocean-refresh-token)
  {
    pattern: /\b(dor_v1_[a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DIGITALOCEAN_REFRESH_TOKEN',
    description: 'Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.',
    contextKeywords: ['dor_v1_'],
  },
  // Discord Api Token (betterleaks: discord-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DISCORD_API_TOKEN',
    description: 'Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.',
    contextKeywords: ['discord'],
  },
  // Discord Client Id (betterleaks: discord-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{18})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DISCORD_CLIENT_ID',
    description: 'Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.',
    contextKeywords: ['discord'],
  },
  // Discord Client Secret (betterleaks: discord-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DISCORD_CLIENT_SECRET',
    description: 'Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.',
    contextKeywords: ['discord'],
  },
  // Doppler Api Token (betterleaks: doppler-api-token)
  {
    pattern: /dp\.pt\.[a-z0-9]{43}/gi,
    type: 'DOPPLER_API_TOKEN',
    description: 'Discovered a Doppler API token, posing a risk to environment and secrets management security.',
    contextKeywords: ['dp.pt.'],
  },
  // Droneci Access Token (betterleaks: droneci-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DRONECI_ACCESS_TOKEN',
    description: 'Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.',
    contextKeywords: ['droneci'],
  },
  // Dropbox Api Token (betterleaks: dropbox-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{15})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DROPBOX_API_TOKEN',
    description: 'Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.',
    contextKeywords: ['dropbox'],
  },
  // Dropbox Long Lived Api Token (betterleaks: dropbox-long-lived-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DROPBOX_LONG_LIVED_API_TOKEN',
    description: 'Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.',
    contextKeywords: ['dropbox'],
  },
  // Dropbox Short Lived Api Token (betterleaks: dropbox-short-lived-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'DROPBOX_SHORT_LIVED_API_TOKEN',
    description: 'Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.',
    contextKeywords: ['dropbox'],
  },
  // Duffel Api Token (betterleaks: duffel-api-token)
  {
    pattern: /duffel_(?:test|live)_[a-z0-9_\-=]{43}/gi,
    type: 'DUFFEL_API_TOKEN',
    description: 'Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.',
    contextKeywords: ['duffel_'],
  },
  // Dynatrace Api Token (betterleaks: dynatrace-api-token)
  {
    pattern: /dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}/gi,
    type: 'DYNATRACE_API_TOKEN',
    description: 'Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.',
    contextKeywords: ['dt0c01.'],
  },
  // Easypost Api Token (betterleaks: easypost-api-token)
  {
    pattern: /\bEZAK[a-z0-9]{54}\b/gi,
    type: 'EASYPOST_API_TOKEN',
    description: 'Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.',
    contextKeywords: ['ezak'],
  },
  // Easypost Test Api Token (betterleaks: easypost-test-api-token)
  {
    pattern: /\bEZTK[a-z0-9]{54}\b/gi,
    type: 'EASYPOST_TEST_API_TOKEN',
    description: 'Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.',
    contextKeywords: ['eztk'],
  },
  // Elevenlabs Api Key (betterleaks: elevenlabs-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:elevenlabs)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(sk_[0-9a-f]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ELEVENLABS_API_KEY',
    description: 'Detected an ElevenLabs API Key, which may expose AI voice synthesis services to unauthorized access.',
    contextKeywords: ['elevenlabs'],
  },
  // Endorlabs Api Key (betterleaks: endorlabs-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:endor(?:labs)?|key)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(endr\+[A-Za-z0-9-]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ENDORLABS_API_KEY',
    description: 'Detected an Endor Labs API Key, which may compromise supply chain security scanning and software composition analysis.',
    contextKeywords: ['endr+'],
  },
  // Endorlabs Api Secret (betterleaks: endorlabs-api-secret)
  {
    pattern: /[\w.-]{0,50}?(?:endor(?:labs)?|secret)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(endr\+[A-Za-z0-9-]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ENDORLABS_API_SECRET',
    description: 'Detected an Endor Labs API Secret, which together with an API key grants full access to Endor Labs supply chain security services.',
    contextKeywords: ['endr+'],
  },
  // Etsy Access Token (betterleaks: etsy-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ETSY_ACCESS_TOKEN',
    description: 'Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.',
    contextKeywords: ['etsy'],
  },
  // Facebook Access Token (betterleaks: facebook-access-token)
  {
    pattern: /\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FACEBOOK_ACCESS_TOKEN',
    description: 'Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.',
    contextKeywords: ['facebook'],
  },
  // Facebook Page Access Token (betterleaks: facebook-page-access-token)
  {
    pattern: /\b(EAA[MC][a-z0-9]{100,})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FACEBOOK_PAGE_ACCESS_TOKEN',
    description: 'Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.',
    contextKeywords: [],
  },
  // Facebook Secret (betterleaks: facebook-secret)
  {
    pattern: /[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FACEBOOK_SECRET',
    description: 'Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.',
    contextKeywords: ['facebook'],
  },
  // Fastly Api Token (betterleaks: fastly-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FASTLY_API_TOKEN',
    description: 'Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.',
    contextKeywords: ['fastly'],
  },
  // Finicity Api Token (betterleaks: finicity-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FINICITY_API_TOKEN',
    description: 'Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.',
    contextKeywords: ['finicity'],
  },
  // Finicity Client Secret (betterleaks: finicity-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FINICITY_CLIENT_SECRET',
    description: 'Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.',
    contextKeywords: ['finicity'],
  },
  // Finnhub Access Token (betterleaks: finnhub-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FINNHUB_ACCESS_TOKEN',
    description: 'Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.',
    contextKeywords: ['finnhub'],
  },
  // Flickr Access Token (betterleaks: flickr-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FLICKR_ACCESS_TOKEN',
    description: 'Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.',
    contextKeywords: ['flickr'],
  },
  // Flutterwave Encryption Key (betterleaks: flutterwave-encryption-key)
  {
    pattern: /FLWSECK_TEST-[a-h0-9]{12}/gi,
    type: 'FLUTTERWAVE_ENCRYPTION_KEY',
    description: 'Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.',
    contextKeywords: ['flwseck_test'],
  },
  // Flutterwave Public Key (betterleaks: flutterwave-public-key)
  {
    pattern: /FLWPUBK_TEST-[a-h0-9]{32}-X/gi,
    type: 'FLUTTERWAVE_PUBLIC_KEY',
    description: 'Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.',
    contextKeywords: ['flwpubk_test'],
  },
  // Flutterwave Secret Key (betterleaks: flutterwave-secret-key)
  {
    pattern: /FLWSECK_TEST-[a-h0-9]{32}-X/gi,
    type: 'FLUTTERWAVE_SECRET_KEY',
    description: 'Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.',
    contextKeywords: ['flwseck_test'],
  },
  // Flyio Access Token (betterleaks: flyio-access-token)
  {
    pattern: /\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'FLYIO_ACCESS_TOKEN',
    description: 'Uncovered a Fly.io API key',
    contextKeywords: [],
  },
  // Frameio Api Token (betterleaks: frameio-api-token)
  {
    pattern: /fio-u-[a-z0-9\-_=]{64}/gi,
    type: 'FRAMEIO_API_TOKEN',
    description: 'Found a Frame.io API token, potentially compromising video collaboration and project management.',
    contextKeywords: ['fio-u-'],
  },
  // Freemius Secret Key (betterleaks: freemius-secret-key)
  {
    pattern: /["\']secret_key["\']\s*=>\s*["\'](sk_[\S]{29})["\']/gi,
    type: 'FREEMIUS_SECRET_KEY',
    description: 'Detected a Freemius secret key, potentially exposing sensitive information.',
    contextKeywords: ['secret_key'],
  },
  // Freshbooks Access Token (betterleaks: freshbooks-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'FRESHBOOKS_ACCESS_TOKEN',
    description: 'Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.',
    contextKeywords: ['freshbooks'],
  },
  // Gcp Api Key (betterleaks: gcp-api-key)
  {
    pattern: /\b(AIza[\w-]{35})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'GCP_API_KEY',
    description: 'Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.',
    contextKeywords: ['aiza'],
  },
  // Gitea Access Token (betterleaks: gitea-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:gitea[_.-]?(?:token|key|secret|access))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GITEA_ACCESS_TOKEN',
    description: 'Detected a Gitea Access Token, which may expose self-hosted Git repositories and associated code to unauthorized access.',
    contextKeywords: ['gitea'],
  },
  // Github App Token (betterleaks: github-app-token)
  {
    pattern: /(?:ghu|ghs)_[0-9a-zA-Z]{36}/g,
    type: 'GITHUB_APP_TOKEN',
    description: 'Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.',
    contextKeywords: [],
  },
  // Github Fine Grained Pat (betterleaks: github-fine-grained-pat)
  {
    pattern: /github_pat_\w{82}/g,
    type: 'GITHUB_FINE_GRAINED_PAT',
    description: 'Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.',
    contextKeywords: ['github_pat_'],
  },
  // Github Oauth (betterleaks: github-oauth)
  {
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    type: 'GITHUB_OAUTH',
    description: 'Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.',
    contextKeywords: ['gho_'],
  },
  // Github Pat (betterleaks: github-pat)
  {
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    type: 'GITHUB_PAT',
    description: 'Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.',
    contextKeywords: ['ghp_'],
  },
  // Github Refresh Token (betterleaks: github-refresh-token)
  {
    pattern: /ghr_[0-9a-zA-Z]{36}/g,
    type: 'GITHUB_REFRESH_TOKEN',
    description: 'Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.',
    contextKeywords: ['ghr_'],
  },
  // Gitlab Cicd Job Token (betterleaks: gitlab-cicd-job-token)
  {
    pattern: /glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}/g,
    type: 'GITLAB_CICD_JOB_TOKEN',
    description: 'Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.',
    contextKeywords: ['glcbt-'],
  },
  // Gitlab Deploy Token (betterleaks: gitlab-deploy-token)
  {
    pattern: /gldt-[0-9a-zA-Z_\-]{20}/g,
    type: 'GITLAB_DEPLOY_TOKEN',
    description: 'Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.',
    contextKeywords: ['gldt-'],
  },
  // Gitlab Feature Flag Client Token (betterleaks: gitlab-feature-flag-client-token)
  {
    pattern: /glffct-[0-9a-zA-Z_\-]{20}/g,
    type: 'GITLAB_FEATURE_FLAG_CLIENT_TOKEN',
    description: 'Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.',
    contextKeywords: ['glffct-'],
  },
  // Gitlab Feed Token (betterleaks: gitlab-feed-token)
  {
    pattern: /glft-[0-9a-zA-Z_\-]{20}/g,
    type: 'GITLAB_FEED_TOKEN',
    description: 'Identified a GitLab feed token, risking exposure of user data.',
    contextKeywords: ['glft-'],
  },
  // Gitlab Incoming Mail Token (betterleaks: gitlab-incoming-mail-token)
  {
    pattern: /glimt-[0-9a-zA-Z_\-]{25}/g,
    type: 'GITLAB_INCOMING_MAIL_TOKEN',
    description: 'Identified a GitLab incoming mail token, risking manipulation of data sent by mail.',
    contextKeywords: ['glimt-'],
  },
  // Gitlab Kubernetes Agent Token (betterleaks: gitlab-kubernetes-agent-token)
  {
    pattern: /glagent-[0-9a-zA-Z_\-]{50}/g,
    type: 'GITLAB_KUBERNETES_AGENT_TOKEN',
    description: 'Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.',
    contextKeywords: ['glagent-'],
  },
  // Gitlab Oauth App Secret (betterleaks: gitlab-oauth-app-secret)
  {
    pattern: /gloas-[0-9a-zA-Z_\-]{64}/g,
    type: 'GITLAB_OAUTH_APP_SECRET',
    description: 'Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.',
    contextKeywords: ['gloas-'],
  },
  // Gitlab Pat (betterleaks: gitlab-pat)
  {
    pattern: /glpat-[\w-]{20}/g,
    type: 'GITLAB_PAT',
    description: 'Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.',
    contextKeywords: ['glpat-'],
  },
  // Gitlab Pat Routable (betterleaks: gitlab-pat-routable)
  {
    pattern: /\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b/g,
    type: 'GITLAB_PAT_ROUTABLE',
    description: 'Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.',
    contextKeywords: ['glpat-'],
  },
  // Gitlab Ptt (betterleaks: gitlab-ptt)
  {
    pattern: /glptt-[0-9a-f]{40}/g,
    type: 'GITLAB_PTT',
    description: 'Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.',
    contextKeywords: ['glptt-'],
  },
  // Gitlab Rrt (betterleaks: gitlab-rrt)
  {
    pattern: /GR1348941[\w-]{20}/g,
    type: 'GITLAB_RRT',
    description: 'Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.',
    contextKeywords: ['gr1348941'],
  },
  // Gitlab Runner Authentication Token (betterleaks: gitlab-runner-authentication-token)
  {
    pattern: /glrt-[0-9a-zA-Z_\-]{20}/g,
    type: 'GITLAB_RUNNER_AUTHENTICATION_TOKEN',
    description: 'Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.',
    contextKeywords: ['glrt-'],
  },
  // Gitlab Runner Authentication Token Routable (betterleaks: gitlab-runner-authentication-token-routable)
  {
    pattern: /\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b/g,
    type: 'GITLAB_RUNNER_AUTHENTICATION_TOKEN_ROUTABLE',
    description: 'Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.',
    contextKeywords: ['glrt-'],
  },
  // Gitlab Scim Token (betterleaks: gitlab-scim-token)
  {
    pattern: /glsoat-[0-9a-zA-Z_\-]{20}/g,
    type: 'GITLAB_SCIM_TOKEN',
    description: 'Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.',
    contextKeywords: ['glsoat-'],
  },
  // Gitlab Session Cookie (betterleaks: gitlab-session-cookie)
  {
    pattern: /_gitlab_session=[0-9a-z]{32}/g,
    type: 'GITLAB_SESSION_COOKIE',
    description: 'Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.',
    contextKeywords: ['_gitlab_session='],
  },
  // Gitter Access Token (betterleaks: gitter-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GITTER_ACCESS_TOKEN',
    description: 'Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.',
    contextKeywords: ['gitter'],
  },
  // Gocardless Api Token (betterleaks: gocardless-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:gocardless)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(live_[a-z0-9\-_=]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GOCARDLESS_API_TOKEN',
    description: 'Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.',
    contextKeywords: [],
  },
  // Grafana Api Key (betterleaks: grafana-api-key)
  {
    pattern: /\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GRAFANA_API_KEY',
    description: 'Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.',
    contextKeywords: ['eyjrijoi'],
  },
  // Grafana Cloud Api Token (betterleaks: grafana-cloud-api-token)
  {
    pattern: /\b(glc_[A-Za-z0-9+\/]{32,400}={0,3})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GRAFANA_CLOUD_API_TOKEN',
    description: 'Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.',
    contextKeywords: ['glc_'],
  },
  // Grafana Service Account Token (betterleaks: grafana-service-account-token)
  {
    pattern: /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GRAFANA_SERVICE_ACCOUNT_TOKEN',
    description: 'Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.',
    contextKeywords: ['glsa_'],
  },
  // Greptile Api Key (betterleaks: greptile-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:greptile)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-zA-Z0-9+\/]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GREPTILE_API_KEY',
    description: 'Detected a Greptile API Key, which may expose AI-powered code search and analysis services to unauthorized access.',
    contextKeywords: ['greptile'],
  },
  // Groq Api Key (betterleaks: groq-api-key)
  {
    pattern: /\b(gsk_[A-Z0-9]{52})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'GROQ_API_KEY',
    description: 'Identified a Groq API Key, which may expose high-speed AI inference services to unauthorized access.',
    contextKeywords: ['gsk_'],
  },
  // Harness Api Key (betterleaks: harness-api-key)
  {
    pattern: /(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}/g,
    type: 'HARNESS_API_KEY',
    description: 'Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.',
    contextKeywords: [],
  },
  // Hashicorp Tf Api Token (betterleaks: hashicorp-tf-api-token)
  {
    pattern: /[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}/gi,
    type: 'HASHICORP_TF_API_TOKEN',
    description: 'Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.',
    contextKeywords: ['atlasv1'],
  },
  // Hashicorp Tf Password (betterleaks: hashicorp-tf-password)
  {
    pattern: /[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'HASHICORP_TF_PASSWORD',
    description: 'Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.',
    contextKeywords: [],
  },
  // Heroku Api Key (betterleaks: heroku-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'HEROKU_API_KEY',
    description: 'Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.',
    contextKeywords: ['heroku'],
  },
  // Heroku Api Key V2 (betterleaks: heroku-api-key-v2)
  {
    pattern: /\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'HEROKU_API_KEY',
    description: 'Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.',
    contextKeywords: ['hrku-aa'],
  },
  // Hubspot Api Key (betterleaks: hubspot-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'HUBSPOT_API_KEY',
    description: 'Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.',
    contextKeywords: ['hubspot'],
  },
  // Huggingface Access Token (betterleaks: huggingface-access-token)
  {
    pattern: /\b(hf_(?i:[a-z]{34}))(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'HUGGINGFACE_ACCESS_TOKEN',
    description: 'Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.',
    contextKeywords: ['hf_'],
  },
  // Huggingface Organization Api Token (betterleaks: huggingface-organization-api-token)
  {
    pattern: /\b(api_org_(?i:[a-z]{34}))(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'HUGGINGFACE_ORGANIZATION_API_TOKEN',
    description: 'Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.',
    contextKeywords: ['api_org_'],
  },
  // Infracost Api Token (betterleaks: infracost-api-token)
  {
    pattern: /\b(ico-[a-zA-Z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'INFRACOST_API_TOKEN',
    description: 'Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.',
    contextKeywords: ['ico-'],
  },
  // Intercom Api Key (betterleaks: intercom-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{60})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'INTERCOM_API_KEY',
    description: 'Identified an Intercom API Token, which could compromise customer communication channels and data privacy.',
    contextKeywords: ['intercom'],
  },
  // Intra42 Client Secret (betterleaks: intra42-client-secret)
  {
    pattern: /\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'INTRA42_CLIENT_SECRET',
    description: 'Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.',
    contextKeywords: [],
  },
  // Jfrog Api Key (betterleaks: jfrog-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{73})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'JFROG_API_KEY',
    description: 'Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.',
    contextKeywords: [],
  },
  // Jfrog Identity Token (betterleaks: jfrog-identity-token)
  {
    pattern: /[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'JFROG_IDENTITY_TOKEN',
    description: 'Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.',
    contextKeywords: [],
  },
  // Jwt (betterleaks: jwt)
  {
    pattern: /\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'JWT',
    description: 'Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.',
    contextKeywords: ['ey'],
  },
  // Kraken Access Token (betterleaks: kraken-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'KRAKEN_ACCESS_TOKEN',
    description: 'Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.',
    contextKeywords: ['kraken'],
  },
  // Kubernetes Secret Yaml (betterleaks: kubernetes-secret-yaml)
  {
    pattern: /(?:\bkind:[ \t]*["\']?\bsecret\b["\']?(?s:.){0,200}?\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["\']?[a-z0-9+\/]{10,}={0,3}["\']?|\{\{[ \t\w"|$:=,.-]+}}|""|\'\'))|\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["\']?[a-z0-9+\/]{10,}={0,3}["\']?|\{\{[ \t\w"|$:=,.-]+}}|""|\'\'))(?s:.){0,200}?\bkind:[ \t]*["\']?\bsecret\b["\']?)/gi,
    type: 'KUBERNETES_SECRET_YAML',
    description: 'Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments',
    contextKeywords: ['secret'],
  },
  // Kucoin Access Token (betterleaks: kucoin-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'KUCOIN_ACCESS_TOKEN',
    description: 'Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.',
    contextKeywords: ['kucoin'],
  },
  // Kucoin Secret Key (betterleaks: kucoin-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'KUCOIN_SECRET_KEY',
    description: 'Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.',
    contextKeywords: ['kucoin'],
  },
  // Launchdarkly Access Token (betterleaks: launchdarkly-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LAUNCHDARKLY_ACCESS_TOKEN',
    description: 'Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.',
    contextKeywords: ['launchdarkly'],
  },
  // Linear Api Key (betterleaks: linear-api-key)
  {
    pattern: /lin_api_[a-z0-9]{40}/gi,
    type: 'LINEAR_API_KEY',
    description: 'Detected a Linear API Token, posing a risk to project management tools and sensitive task data.',
    contextKeywords: ['lin_api_'],
  },
  // Linear Client Secret (betterleaks: linear-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:linear)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LINEAR_CLIENT_SECRET',
    description: 'Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.',
    contextKeywords: ['linear'],
  },
  // Linkedin Client Id (betterleaks: linkedin-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{14})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LINKEDIN_CLIENT_ID',
    description: 'Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.',
    contextKeywords: [],
  },
  // Linkedin Client Secret (betterleaks: linkedin-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LINKEDIN_CLIENT_SECRET',
    description: 'Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.',
    contextKeywords: [],
  },
  // Lob Api Key (betterleaks: lob-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}((live|test)_[a-f0-9]{35})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LOB_API_KEY',
    description: 'Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.',
    contextKeywords: [],
  },
  // Lob Pub Api Key (betterleaks: lob-pub-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LOB_PUB_API_KEY',
    description: 'Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.',
    contextKeywords: [],
  },
  // Looker Client Id (betterleaks: looker-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{20})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LOOKER_CLIENT_ID',
    description: 'Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.',
    contextKeywords: ['looker'],
  },
  // Looker Client Secret (betterleaks: looker-client-secret)
  {
    pattern: /[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'LOOKER_CLIENT_SECRET',
    description: 'Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.',
    contextKeywords: ['looker'],
  },
  // Mailchimp Api Key (betterleaks: mailchimp-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32}-us\d\d)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MAILCHIMP_API_KEY',
    description: 'Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.',
    contextKeywords: ['mailchimp'],
  },
  // Mailgun Private Api Token (betterleaks: mailgun-private-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(key-[a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MAILGUN_PRIVATE_API_TOKEN',
    description: 'Found a Mailgun private API token, risking unauthorized email service operations and data breaches.',
    contextKeywords: ['mailgun'],
  },
  // Mailgun Pub Key (betterleaks: mailgun-pub-key)
  {
    pattern: /[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(pubkey-[a-f0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MAILGUN_PUB_KEY',
    description: 'Discovered a Mailgun public validation key, which could expose email verification processes and associated data.',
    contextKeywords: ['mailgun'],
  },
  // Mailgun Signing Key (betterleaks: mailgun-signing-key)
  {
    pattern: /[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MAILGUN_SIGNING_KEY',
    description: 'Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.',
    contextKeywords: ['mailgun'],
  },
  // Mapbox Api Token (betterleaks: mapbox-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MAPBOX_API_TOKEN',
    description: 'Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.',
    contextKeywords: ['mapbox'],
  },
  // Mattermost Access Token (betterleaks: mattermost-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:mattermost)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{26})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MATTERMOST_ACCESS_TOKEN',
    description: 'Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.',
    contextKeywords: ['mattermost'],
  },
  // Maxmind License Key (betterleaks: maxmind-license-key)
  {
    pattern: /\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'MAXMIND_LICENSE_KEY',
    description: 'Discovered a potential MaxMind license key.',
    contextKeywords: ['_mmk'],
  },
  // Messagebird Api Token (betterleaks: messagebird-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{25})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MESSAGEBIRD_API_TOKEN',
    description: 'Found a MessageBird API token, risking unauthorized access to communication platforms and message data.',
    contextKeywords: [],
  },
  // Messagebird Client Id (betterleaks: messagebird-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MESSAGEBIRD_CLIENT_ID',
    description: 'Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.',
    contextKeywords: [],
  },
  // Microsoft Teams Webhook (betterleaks: microsoft-teams-webhook)
  {
    pattern: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/g,
    type: 'MICROSOFT_TEAMS_WEBHOOK',
    description: 'Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.',
    contextKeywords: [],
  },
  // Mistral Api Key (betterleaks: mistral-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:mistral)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([A-Z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'MISTRAL_API_KEY',
    description: 'Detected a Mistral AI API Key, which may expose AI language model services to unauthorized access.',
    contextKeywords: ['mistral'],
  },
  // Netlify Access Token (betterleaks: netlify-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:netlify)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{40,46})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NETLIFY_ACCESS_TOKEN',
    description: 'Detected a Netlify Access Token, potentially compromising web hosting services and site management.',
    contextKeywords: ['netlify'],
  },
  // New Relic Browser Api Token (betterleaks: new-relic-browser-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(NRJS-[a-f0-9]{19})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NEW_RELIC_BROWSER_API_TOKEN',
    description: 'Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.',
    contextKeywords: ['nrjs-'],
  },
  // New Relic Insert Key (betterleaks: new-relic-insert-key)
  {
    pattern: /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(NRII-[a-z0-9-]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NEW_RELIC_INSERT_KEY',
    description: 'Discovered a New Relic insight insert key, compromising data injection into the platform.',
    contextKeywords: ['nrii-'],
  },
  // New Relic User Api Id (betterleaks: new-relic-user-api-id)
  {
    pattern: /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NEW_RELIC_USER_API_ID',
    description: 'Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.',
    contextKeywords: [],
  },
  // New Relic User Api Key (betterleaks: new-relic-user-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(NRAK-[a-z0-9]{27})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NEW_RELIC_USER_API_KEY',
    description: 'Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.',
    contextKeywords: ['nrak'],
  },
  // Notion Api Token (betterleaks: notion-api-token)
  {
    pattern: /\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'NOTION_API_TOKEN',
    description: 'Notion API token',
    contextKeywords: ['ntn_'],
  },
  // Npm Access Token (betterleaks: npm-access-token)
  {
    pattern: /\b(npm_[a-z0-9]{36})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NPM_ACCESS_TOKEN',
    description: 'Uncovered an npm access token, potentially compromising package management and code repository access.',
    contextKeywords: ['npm_'],
  },
  // Nuget Config Password (betterleaks: nuget-config-password)
  {
    pattern: /<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*\/>/gi,
    type: 'NUGET_CONFIG_PASSWORD',
    description: 'Identified a password within a Nuget config file, potentially compromising package management access.',
    contextKeywords: ['<add key='],
  },
  // Nvidia Api Key (betterleaks: nvidia-api-key)
  {
    pattern: /\b(nvapi-[A-Z0-9_-]{60,70})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NVIDIA_API_KEY',
    description: 'Detected an NVIDIA NIM API Key, which may expose AI inference and GPU cloud services to unauthorized access.',
    contextKeywords: ['nvapi-'],
  },
  // Nytimes Access Token (betterleaks: nytimes-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9=_\-]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'NYTIMES_ACCESS_TOKEN',
    description: 'Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.',
    contextKeywords: [],
  },
  // Octopus Deploy Api Key (betterleaks: octopus-deploy-api-key)
  {
    pattern: /\b(API-[A-Z0-9]{26})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'OCTOPUS_DEPLOY_API_KEY',
    description: 'Discovered a potential Octopus Deploy API key, risking application deployments and operational security.',
    contextKeywords: ['api-'],
  },
  // Okta Access Token (betterleaks: okta-access-token)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(00[\w=\-]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'OKTA_ACCESS_TOKEN',
    description: 'Identified an Okta Access Token, which may compromise identity management services and user authentication data.',
    contextKeywords: ['okta'],
  },
  // Ollama Api Key (betterleaks: ollama-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:ollama)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{32}\.[a-zA-Z0-9_-]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'OLLAMA_API_KEY',
    description: 'Detected an Ollama API Key, which may expose local and hosted AI model serving to unauthorized access.',
    contextKeywords: ['ollama'],
  },
  // Openai Api Key (betterleaks: openai-api-key)
  {
    pattern: /\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58}|[A-Za-z0-9_-]{20})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'OPENAI_API_KEY',
    description: 'Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.',
    contextKeywords: ['t3blbkfj'],
  },
  // Openrouter Api Key (betterleaks: openrouter-api-key)
  {
    pattern: /\b(sk-or-v1-[0-9a-f]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'OPENROUTER_API_KEY',
    description: 'Detected an OpenRouter API Key, which may expose access to multiple AI models through the OpenRouter gateway.',
    contextKeywords: ['sk-or-v1-'],
  },
  // Openshift User Token (betterleaks: openshift-user-token)
  {
    pattern: /\b(sha256~[\w-]{43})(?:[^\w-]|\z)/g,
    type: 'OPENSHIFT_USER_TOKEN',
    description: 'Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.',
    contextKeywords: ['sha256~'],
  },
  // Plaid Api Token (betterleaks: plaid-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'PLAID_API_TOKEN',
    description: 'Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.',
    contextKeywords: ['plaid'],
  },
  // Plaid Client Id (betterleaks: plaid-client-id)
  {
    pattern: /[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'PLAID_CLIENT_ID',
    description: 'Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.',
    contextKeywords: ['plaid'],
  },
  // Plaid Secret Key (betterleaks: plaid-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{30})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'PLAID_SECRET_KEY',
    description: 'Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.',
    contextKeywords: ['plaid'],
  },
  // Planetscale Api Token (betterleaks: planetscale-api-token)
  {
    pattern: /\b(pscale_tkn_[\w=\.-]{32,64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'PLANETSCALE_API_TOKEN',
    description: 'Identified a PlanetScale API token, potentially compromising database management and operations.',
    contextKeywords: ['pscale_tkn_'],
  },
  // Planetscale Id (betterleaks: planetscale-id)
  {
    pattern: /(?:pscale|planetscale)(?:.|[\n\r]){0,16}?(?:USER|ID|NAME)(?:.|[\n\r]){0,16}?([a-z0-9]{12})/gi,
    type: 'PLANETSCALE_ID',
    description: 'Found a PlanetScale service token ID.',
    contextKeywords: [],
  },
  // Planetscale Oauth Token (betterleaks: planetscale-oauth-token)
  {
    pattern: /\b(pscale_oauth_[\w=\.-]{32,64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'PLANETSCALE_OAUTH_TOKEN',
    description: 'Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.',
    contextKeywords: ['pscale_oauth_'],
  },
  // Planetscale Password (betterleaks: planetscale-password)
  {
    pattern: /\b(pscale_pw_[\w=\.-]{32,64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'PLANETSCALE_PASSWORD',
    description: 'Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.',
    contextKeywords: ['pscale_pw_'],
  },
  // Posthog Personal Api Key (betterleaks: posthog-personal-api-key)
  {
    pattern: /\b(phx_[a-zA-Z0-9_\-]{47})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'POSTHOG_PERSONAL_API_KEY',
    description: 'Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects.',
    contextKeywords: ['phx_'],
  },
  // Posthog Project Api Key (betterleaks: posthog-project-api-key)
  {
    pattern: /\b(phc_[a-zA-Z0-9_\-]{43})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'POSTHOG_PROJECT_API_KEY',
    description: 'Detected a PostHog Project API Key, which may expose product analytics data and event tracking to unauthorized access.',
    contextKeywords: ['phc_'],
  },
  // Postman Api Token (betterleaks: postman-api-token)
  {
    pattern: /\b(PMAK-[a-f0-9]{24}\-[a-f0-9]{34})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'POSTMAN_API_TOKEN',
    description: 'Uncovered a Postman API token, potentially compromising API testing and development workflows.',
    contextKeywords: ['pmak-'],
  },
  // Prefect Api Token (betterleaks: prefect-api-token)
  {
    pattern: /\b(pnu_[a-zA-Z0-9]{36})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'PREFECT_API_TOKEN',
    description: 'Detected a Prefect API token, risking unauthorized access to workflow management and automation services.',
    contextKeywords: ['pnu_'],
  },
  // Privateai Api Token (betterleaks: privateai-api-token)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:private[_-]?ai)(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{32})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'PRIVATEAI_API_TOKEN',
    description: 'Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.',
    contextKeywords: [],
  },
  // Pulumi Api Token (betterleaks: pulumi-api-token)
  {
    pattern: /\b(pul-[a-f0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'PULUMI_API_TOKEN',
    description: 'Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.',
    contextKeywords: ['pul-'],
  },
  // Pypi Upload Token (betterleaks: pypi-upload-token)
  {
    pattern: /pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}/g,
    type: 'PYPI_UPLOAD_TOKEN',
    description: 'Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.',
    contextKeywords: ['pypi-ageichlwas5vcmc'],
  },
  // Rapidapi Access Token (betterleaks: rapidapi-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:rapidapi)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9_-]{50})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'RAPIDAPI_ACCESS_TOKEN',
    description: 'Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.',
    contextKeywords: ['rapidapi'],
  },
  // Readme Api Token (betterleaks: readme-api-token)
  {
    pattern: /\b(rdme_[a-z0-9]{70})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'README_API_TOKEN',
    description: 'Detected a Readme API token, risking unauthorized documentation management and content exposure.',
    contextKeywords: ['rdme_'],
  },
  // Replicate Api Token (betterleaks: replicate-api-token)
  {
    pattern: /\b(r8_[A-Za-z0-9]{37})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'REPLICATE_API_TOKEN',
    description: 'Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access.',
    contextKeywords: ['r8_'],
  },
  // Rubygems Api Token (betterleaks: rubygems-api-token)
  {
    pattern: /\b(rubygems_[a-f0-9]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'RUBYGEMS_API_TOKEN',
    description: 'Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.',
    contextKeywords: ['rubygems_'],
  },
  // Scalingo Api Token (betterleaks: scalingo-api-token)
  {
    pattern: /\b(tk-us-[\w-]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SCALINGO_API_TOKEN',
    description: 'Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.',
    contextKeywords: ['tk-us-'],
  },
  // Sendbird Access Id (betterleaks: sendbird-access-id)
  {
    pattern: /[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SENDBIRD_ACCESS_ID',
    description: 'Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.',
    contextKeywords: ['sendbird'],
  },
  // Sendbird Access Token (betterleaks: sendbird-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SENDBIRD_ACCESS_TOKEN',
    description: 'Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.',
    contextKeywords: ['sendbird'],
  },
  // Sendgrid Api Token (betterleaks: sendgrid-api-token)
  {
    pattern: /\b(SG\.[a-z0-9=_\-\.]{66})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SENDGRID_API_TOKEN',
    description: 'Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.',
    contextKeywords: ['sg.'],
  },
  // Sendinblue Api Token (betterleaks: sendinblue-api-token)
  {
    pattern: /\b(xkeysib-[a-f0-9]{64}\-[a-z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SENDINBLUE_API_TOKEN',
    description: 'Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.',
    contextKeywords: ['xkeysib-'],
  },
  // Sentry Access Token (betterleaks: sentry-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SENTRY_ACCESS_TOKEN',
    description: 'Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data.',
    contextKeywords: ['sentry'],
  },
  // Sentry Org Token (betterleaks: sentry-org-token)
  {
    pattern: /\bsntrys_eyJpYXQiO[a-zA-Z0-9+\/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+\/]{10,200}={0,2}_[a-zA-Z0-9+\/]{43}(?:[^a-zA-Z0-9+\/]|\z)/g,
    type: 'SENTRY_ORG_TOKEN',
    description: 'Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data.',
    contextKeywords: ['sntrys_eyjpyxqio'],
  },
  // Sentry User Token (betterleaks: sentry-user-token)
  {
    pattern: /\b(sntryu_[a-f0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SENTRY_USER_TOKEN',
    description: 'Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.',
    contextKeywords: ['sntryu_'],
  },
  // Settlemint Application Access Token (betterleaks: settlemint-application-access-token)
  {
    pattern: /\b(sm_aat_[a-zA-Z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SETTLEMINT_APPLICATION_ACCESS_TOKEN',
    description: 'Found a Settlemint Application Access Token.',
    contextKeywords: ['sm_aat'],
  },
  // Settlemint Personal Access Token (betterleaks: settlemint-personal-access-token)
  {
    pattern: /\b(sm_pat_[a-zA-Z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SETTLEMINT_PERSONAL_ACCESS_TOKEN',
    description: 'Found a Settlemint Personal Access Token.',
    contextKeywords: ['sm_pat'],
  },
  // Settlemint Service Access Token (betterleaks: settlemint-service-access-token)
  {
    pattern: /\b(sm_sat_[a-zA-Z0-9]{16})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SETTLEMINT_SERVICE_ACCESS_TOKEN',
    description: 'Found a Settlemint Service Access Token.',
    contextKeywords: ['sm_sat'],
  },
  // Shippo Api Token (betterleaks: shippo-api-token)
  {
    pattern: /\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SHIPPO_API_TOKEN',
    description: 'Discovered a Shippo API token, potentially compromising shipping services and customer order data.',
    contextKeywords: ['shippo_'],
  },
  // Shopify Access Token (betterleaks: shopify-access-token)
  {
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    type: 'SHOPIFY_ACCESS_TOKEN',
    description: 'Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.',
    contextKeywords: ['shpat_'],
  },
  // Shopify Custom Access Token (betterleaks: shopify-custom-access-token)
  {
    pattern: /shpca_[a-fA-F0-9]{32}/g,
    type: 'SHOPIFY_CUSTOM_ACCESS_TOKEN',
    description: 'Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.',
    contextKeywords: ['shpca_'],
  },
  // Shopify Private App Access Token (betterleaks: shopify-private-app-access-token)
  {
    pattern: /shppa_[a-fA-F0-9]{32}/g,
    type: 'SHOPIFY_PRIVATE_APP_ACCESS_TOKEN',
    description: 'Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.',
    contextKeywords: ['shppa_'],
  },
  // Shopify Shared Secret (betterleaks: shopify-shared-secret)
  {
    pattern: /shpss_[a-fA-F0-9]{32}/g,
    type: 'SHOPIFY_SHARED_SECRET',
    description: 'Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.',
    contextKeywords: ['shpss_'],
  },
  // Sidekiq Secret (betterleaks: sidekiq-secret)
  {
    pattern: /[\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SIDEKIQ_SECRET',
    description: 'Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.',
    contextKeywords: [],
  },
  // Sidekiq Sensitive Url (betterleaks: sidekiq-sensitive-url)
  {
    pattern: /\bhttps?:\/\/([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)/gi,
    type: 'SIDEKIQ_SENSITIVE_URL',
    description: 'Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.',
    contextKeywords: [],
  },
  // Slack App Token (betterleaks: slack-app-token)
  {
    pattern: /xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+/gi,
    type: 'SLACK_APP_TOKEN',
    description: 'Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.',
    contextKeywords: ['xapp'],
  },
  // Slack Bot Token (betterleaks: slack-bot-token)
  {
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    type: 'SLACK_BOT_TOKEN',
    description: 'Identified a Slack Bot token, which may compromise bot integrations and communication channel security.',
    contextKeywords: ['xoxb'],
  },
  // Slack Config Access Token (betterleaks: slack-config-access-token)
  {
    pattern: /xoxe.xox[bp]-\d-[A-Z0-9]{163,166}/gi,
    type: 'SLACK_CONFIG_ACCESS_TOKEN',
    description: 'Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.',
    contextKeywords: [],
  },
  // Slack Config Refresh Token (betterleaks: slack-config-refresh-token)
  {
    pattern: /xoxe-\d-[A-Z0-9]{146}/gi,
    type: 'SLACK_CONFIG_REFRESH_TOKEN',
    description: 'Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.',
    contextKeywords: ['xoxe-'],
  },
  // Slack Legacy Bot Token (betterleaks: slack-legacy-bot-token)
  {
    pattern: /xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}/g,
    type: 'SLACK_LEGACY_BOT_TOKEN',
    description: 'Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.',
    contextKeywords: ['xoxb'],
  },
  // Slack Legacy Token (betterleaks: slack-legacy-token)
  {
    pattern: /xox[os]-\d+-\d+-\d+-[a-fA-F\d]+/g,
    type: 'SLACK_LEGACY_TOKEN',
    description: 'Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.',
    contextKeywords: [],
  },
  // Slack Legacy Workspace Token (betterleaks: slack-legacy-workspace-token)
  {
    pattern: /xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}/g,
    type: 'SLACK_LEGACY_WORKSPACE_TOKEN',
    description: 'Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.',
    contextKeywords: [],
  },
  // Slack User Token (betterleaks: slack-user-token)
  {
    pattern: /xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}/g,
    type: 'SLACK_USER_TOKEN',
    description: 'Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.',
    contextKeywords: [],
  },
  // Slack Webhook Url (betterleaks: slack-webhook-url)
  {
    pattern: /(?:https?:\/\/)?hooks.slack.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+\/]{43,56}/g,
    type: 'SLACK_WEBHOOK_URL',
    description: 'Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.',
    contextKeywords: ['hooks.slack.com'],
  },
  // Snyk Api Token (betterleaks: snyk-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SNYK_API_TOKEN',
    description: 'Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.',
    contextKeywords: ['snyk'],
  },
  // Sonar Api Token (betterleaks: sonar-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\-]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SONAR_API_TOKEN',
    description: 'Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.',
    contextKeywords: ['sonar'],
  },
  // Sourcegraph Access Token (betterleaks: sourcegraph-access-token)
  {
    pattern: /\b(\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b)(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SOURCEGRAPH_ACCESS_TOKEN',
    description: 'Sourcegraph is a code search and navigation engine.',
    contextKeywords: [],
  },
  // Square Access Token (betterleaks: square-access-token)
  {
    pattern: /\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SQUARE_ACCESS_TOKEN',
    description: 'Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.',
    contextKeywords: [],
  },
  // Squarespace Access Token (betterleaks: squarespace-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:squarespace)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SQUARESPACE_ACCESS_TOKEN',
    description: 'Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.',
    contextKeywords: ['squarespace'],
  },
  // Stability Ai Api Key (betterleaks: stability-ai-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:stability)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(sk-[A-Za-z0-9]{48})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'STABILITY_AI_API_KEY',
    description: 'Detected a Stability AI API Key, which may expose AI image generation services to unauthorized access.',
    contextKeywords: ['stability'],
  },
  // Stripe Access Token (betterleaks: stripe-access-token)
  {
    pattern: /\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'STRIPE_ACCESS_TOKEN',
    description: 'Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.',
    contextKeywords: [],
  },
  // Sumologic Access Id (betterleaks: sumologic-access-id)
  {
    pattern: /[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s\'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(su[a-zA-Z0-9]{12})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'SUMOLOGIC_ACCESS_ID',
    description: 'Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.',
    contextKeywords: ['sumo'],
  },
  // Sumologic Access Token (betterleaks: sumologic-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{64})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'SUMOLOGIC_ACCESS_TOKEN',
    description: 'Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.',
    contextKeywords: ['sumo'],
  },
  // Telegram Bot Api Token (betterleaks: telegram-bot-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TELEGRAM_BOT_API_TOKEN',
    description: 'Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.',
    contextKeywords: ['telegr'],
  },
  // Togetherai Api Key (betterleaks: togetherai-api-key)
  {
    pattern: /\b(tgp_v1_[A-Za-z0-9_-]{43})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TOGETHERAI_API_KEY',
    description: 'Detected a Together.ai API Key, which may expose access to open-source AI models and inference services.',
    contextKeywords: ['tgp_v1_'],
  },
  // Travisci Access Token (betterleaks: travisci-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:travis)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{22})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TRAVISCI_ACCESS_TOKEN',
    description: 'Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.',
    contextKeywords: ['travis'],
  },
  // Twilio Api Key (betterleaks: twilio-api-key)
  {
    pattern: /SK[0-9a-fA-F]{32}/g,
    type: 'TWILIO_API_KEY',
    description: 'Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.',
    contextKeywords: ['sk'],
  },
  // Twitch Api Token (betterleaks: twitch-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:twitch)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{30})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITCH_API_TOKEN',
    description: 'Discovered a Twitch API token, which could compromise streaming services and account integrations.',
    contextKeywords: ['twitch'],
  },
  // Twitter Access Secret (betterleaks: twitter-access-secret)
  {
    pattern: /[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{45})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITTER_ACCESS_SECRET',
    description: 'Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.',
    contextKeywords: ['twitter'],
  },
  // Twitter Access Token (betterleaks: twitter-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITTER_ACCESS_TOKEN',
    description: 'Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.',
    contextKeywords: ['twitter'],
  },
  // Twitter Api Key (betterleaks: twitter-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{25})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITTER_API_KEY',
    description: 'Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.',
    contextKeywords: ['twitter'],
  },
  // Twitter Api Secret (betterleaks: twitter-api-secret)
  {
    pattern: /[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{50})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITTER_API_SECRET',
    description: 'Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.',
    contextKeywords: ['twitter'],
  },
  // Twitter Bearer Token (betterleaks: twitter-bearer-token)
  {
    pattern: /[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TWITTER_BEARER_TOKEN',
    description: 'Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.',
    contextKeywords: ['twitter'],
  },
  // Typeform Api Token (betterleaks: typeform-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'TYPEFORM_API_TOKEN',
    description: 'Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.',
    contextKeywords: ['tfp_'],
  },
  // Vault Batch Token (betterleaks: vault-batch-token)
  {
    pattern: /\b(hvb\.[\w-]{138,300})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'VAULT_BATCH_TOKEN',
    description: 'Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.',
    contextKeywords: ['hvb.'],
  },
  // Vault Service Token (betterleaks: vault-service-token)
  {
    pattern: /\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/g,
    type: 'VAULT_SERVICE_TOKEN',
    description: 'Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.',
    contextKeywords: [],
  },
  // Vercel Ai Gateway Key (betterleaks: vercel-ai-gateway-key)
  {
    pattern: /\b(vck_[A-Za-z0-9_-]{56})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_AI_GATEWAY_KEY',
    description: 'Detected a Vercel AI Gateway API Key (vck_), which may expose AI model routing and gateway access to unauthorized parties.',
    contextKeywords: ['vck_'],
  },
  // Vercel Api Token (betterleaks: vercel-api-token)
  {
    pattern: /[\w.-]{0,50}?(?:vercel)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([A-Z0-9]{24})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_API_TOKEN',
    description: 'Detected a Vercel API Token, which may expose deployment and serverless infrastructure to unauthorized access.',
    contextKeywords: ['vercel'],
  },
  // Vercel App Access Token (betterleaks: vercel-app-access-token)
  {
    pattern: /\b(vca_[A-Za-z0-9_-]{56})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_APP_ACCESS_TOKEN',
    description: 'Detected a Vercel App Access Token (vca_), which may allow Sign in with Vercel apps to access user resources.',
    contextKeywords: ['vca_'],
  },
  // Vercel App Refresh Token (betterleaks: vercel-app-refresh-token)
  {
    pattern: /\b(vcr_[A-Za-z0-9_-]{56})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_APP_REFRESH_TOKEN',
    description: 'Detected a Vercel App Refresh Token (vcr_), which may allow persistent unauthorized access through token refresh flows.',
    contextKeywords: ['vcr_'],
  },
  // Vercel Integration Token (betterleaks: vercel-integration-token)
  {
    pattern: /\b(vci_[A-Za-z0-9_-]{56})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_INTEGRATION_TOKEN',
    description: 'Detected a Vercel Integration Token (vci_), which may allow third-party service integrations to act on behalf of users.',
    contextKeywords: ['vci_'],
  },
  // Vercel Personal Access Token (betterleaks: vercel-personal-access-token)
  {
    pattern: /\b(vcp_[A-Za-z0-9_-]{56})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'VERCEL_PERSONAL_ACCESS_TOKEN',
    description: 'Detected a Vercel Personal Access Token (vcp_), which may expose full account and deployment management capabilities.',
    contextKeywords: ['vcp_'],
  },
  // Weights And Biases Api Key (betterleaks: weights-and-biases-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:wandb|weightsandbiases)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-f0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'WEIGHTS_AND_BIASES_API_KEY',
    description: 'Detected a Weights & Biases API Key, which may expose ML experiment tracking and model registry access to unauthorized parties.',
    contextKeywords: [],
  },
  // Weights And Biases Api Key V1 (betterleaks: weights-and-biases-api-key-v1)
  {
    pattern: /\b(wandb_v1_[A-Za-z0-9_]{77})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'WEIGHTS_AND_BIASES_API_KEY',
    description: 'Detected a Weights & Biases v1 API Key (wandb_v1_), which may expose ML experiment tracking and artifact storage to unauthorized access.',
    contextKeywords: ['wandb_v1_'],
  },
  // Xai Api Key (betterleaks: xai-api-key)
  {
    pattern: /\b(xai-[A-Za-z0-9_-]{70,120})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'XAI_API_KEY',
    description: 'Detected an xAI (Grok) API Key, which may expose Grok AI model access to unauthorized parties.',
    contextKeywords: ['xai-'],
  },
  // Yandex Access Token (betterleaks: yandex-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'YANDEX_ACCESS_TOKEN',
    description: 'Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.',
    contextKeywords: ['yandex'],
  },
  // Yandex Api Key (betterleaks: yandex-api-key)
  {
    pattern: /[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'YANDEX_API_KEY',
    description: 'Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.',
    contextKeywords: ['yandex'],
  },
  // Yandex Aws Access Token (betterleaks: yandex-aws-access-token)
  {
    pattern: /[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}(YC[a-zA-Z0-9_\-]{38})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'YANDEX_AWS_ACCESS_TOKEN',
    description: 'Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.',
    contextKeywords: ['yandex'],
  },
  // Zendesk Secret Key (betterleaks: zendesk-secret-key)
  {
    pattern: /[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}([a-z0-9]{40})(?:\\?[\'"\x60]|[\s;]|\\[nr]|$)/gi,
    type: 'ZENDESK_SECRET_KEY',
    description: 'Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.',
    contextKeywords: ['zendesk'],
  },
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
