/**
 * Query Catalog
 *
 * The single source of truth for every GitHub search query the scanner can run.
 * Queries are organised as: target (code / commits / issues) → macro area → query.
 *
 * Every query carries a stable `id` that is persisted in the QuerySetting table,
 * so IDs must never be renumbered or renamed once shipped.
 *
 * Templates are raw GitHub search syntax with `{domain}` placeholders, rendered
 * at scan time by renderQuery().
 *
 * GitHub Search limits enforced by these templates:
 *   1. Maximum of 5 OR operators per query. Exceeding this causes a silent failure
 *      (returns 0 results without a 422 error).
 *   2. Never mix filename:/extension: qualifiers with plain terms in the same OR group.
 *   3. Never put "qualifier plain-term" as a single OR operand.
 *   4. The legacy /search/code parser rejects `"domain" (A OR B)`, so the domain is
 *      repeated per operand: `"domain" A OR "domain" B`.
 */

export type QueryTarget = 'code' | 'commits' | 'issues';

export interface QueryDefinition {
  /** Stable slug — persisted in the database, never renumber. */
  id: string;
  /** Human-readable name shown in the Queries UI. */
  label: string;
  /** Raw GitHub search syntax with `{domain}` placeholders. */
  template: string;
}

export interface QueryArea {
  id: string;
  target: QueryTarget;
  name: string;
  description: string;
  queries: QueryDefinition[];
}

export const TARGET_LABELS: Record<QueryTarget, string> = {
  code: 'Code Search',
  commits: 'Commit Search',
  issues: 'Issue Search',
};

export const TARGET_DESCRIPTIONS: Record<QueryTarget, string> = {
  code: 'Searches file contents across public repositories, forks and wikis.',
  commits: 'Searches commit messages and author/committer metadata.',
  issues: 'Searches issue and pull request titles and bodies.',
};

/** Build helper: `"{domain}" term` */
const q = (term: string) => `"{domain}" ${term}`;
/** Build helper: `"{domain}" A OR "{domain}" B` (repeated-domain OR format) */
const qOr = (...terms: string[]) => terms.map(t => `"{domain}" ${t}`).join(' OR ');

// ===================================================================
// CODE SEARCH
// ===================================================================

const CODE_AREAS: QueryArea[] = [
  {
    id: 'email_discovery',
    target: 'code',
    name: 'Email Discovery',
    description: 'Direct @domain searches that surface corporate email addresses and the credentials near them.',
    queries: [
      { id: 'code.email_discovery.any_mention', label: 'Any @domain mention', template: '"@{domain}"' },
      { id: 'code.email_discovery.credential_words', label: 'Email near credential words', template: '"@{domain}" password OR "@{domain}" passwd OR "@{domain}" pwd OR "@{domain}" credentials OR "@{domain}" secret' },
      { id: 'code.email_discovery.account_words', label: 'Email near account words', template: '"@{domain}" username OR "@{domain}" login OR "@{domain}" account OR "@{domain}" user' },
      { id: 'code.email_discovery.contact_aliases', label: 'Common contact aliases', template: '"@{domain}" email OR "@{domain}" contact OR "@{domain}" admin OR "@{domain}" info OR "@{domain}" support' },
      { id: 'code.email_discovery.token_words', label: 'Email near token/API-key words', template: '"@{domain}" token OR "@{domain}" api_key OR "@{domain}" apikey OR "@{domain}" key' },
      { id: 'code.email_discovery.data_files', label: 'Email in SQL / CSV / TXT files', template: '"@{domain}" extension:sql OR "@{domain}" extension:csv OR "@{domain}" extension:txt' },
      { id: 'code.email_discovery.config_extensions', label: 'Email in config file extensions', template: '"@{domain}" extension:conf OR "@{domain}" extension:ini OR "@{domain}" extension:cfg OR "@{domain}" extension:yaml' },
      { id: 'code.email_discovery.config_filenames', label: 'Email in .env / config / settings files', template: '"@{domain}" filename:.env OR "@{domain}" filename:config OR "@{domain}" filename:settings' },
    ],
  },
  {
    id: 'credentials_auth',
    target: 'code',
    name: 'Credentials & Auth',
    description: 'Private keys, passwords, tokens, OAuth secrets and identity provider credentials.',
    queries: [
      { id: 'code.credentials_auth.private_key_headers', label: 'Private key headers (RSA / OpenSSH / PGP)', template: qOr('"BEGIN PRIVATE KEY"', '"BEGIN RSA PRIVATE KEY"', '"BEGIN OPENSSH PRIVATE KEY"', '"BEGIN PGP PRIVATE KEY"') },
      { id: 'code.credentials_auth.generic_api_key_words', label: 'Generic API key keywords', template: qOr('api_key', 'apikey', 'API_KEY', 'api_secret') },
      { id: 'code.credentials_auth.jwt_bearer', label: 'JWT secrets & bearer tokens', template: qOr('jwt_secret', 'JWT_SECRET', 'bearer') },
      { id: 'code.credentials_auth.oauth_tokens', label: 'OAuth access & refresh tokens', template: qOr('oauth_token', 'access_token', 'refresh_token') },
      { id: 'code.credentials_auth.password_words', label: 'Password keywords', template: qOr('password', 'passwd', 'pwd', 'credentials') },
      { id: 'code.credentials_auth.ssh_keywords', label: 'SSH & deploy key keywords', template: qOr('ssh', 'deploy_key', 'id_rsa', 'known_hosts', 'authorized_keys') },
      { id: 'code.credentials_auth.certificate_files', label: 'Certificate & key files (.pem/.p12/.pfx)', template: qOr('filename:.pem', 'filename:.p12', 'filename:.pfx', 'filename:.key', 'filename:.crt') },
      { id: 'code.credentials_auth.password_text_files', label: 'Password & credential text files', template: qOr('filename:password.txt', 'filename:passwords.txt', 'filename:credentials.txt', 'filename:creds.txt', 'filename:secret.txt') },
      { id: 'code.credentials_auth.identity_provider_secrets', label: 'Okta / Auth0 / Keycloak secrets', template: qOr('okta_token', 'auth0_secret', 'keycloak') },
      { id: 'code.credentials_auth.okta_auth0_tokens', label: 'Okta & Auth0 API tokens', template: qOr('OKTA_API_TOKEN', 'AUTH0_CLIENT_SECRET') },
      { id: 'code.credentials_auth.pem_private_key', label: 'PEM files containing PRIVATE KEY', template: q('extension:pem "PRIVATE KEY"') },
      { id: 'code.credentials_auth.token_prefix_hunting', label: 'Known token prefixes (AKIA / JWT / sk_live)', template: qOr('"AKIA"', '"eyJhbGciOiJIUzI1NiIs"', '"sk_live_"', '"rk_live_"') },
      { id: 'code.credentials_auth.ssh_private_key_files', label: 'SSH private key files by name', template: qOr('filename:id_rsa', 'filename:id_dsa', 'filename:id_ed25519', 'filename:id_ecdsa') },
      { id: 'code.credentials_auth.oauth_secrets', label: 'OAuth client secrets', template: qOr('oauth_secret', 'client_credentials') },
      { id: 'code.credentials_auth.oauth_json', label: 'oauth.json files', template: q('filename:oauth.json') },
      { id: 'code.credentials_auth.client_id_secret_pair', label: 'client_id + client_secret pairs', template: q('client_id client_secret') },
      { id: 'code.credentials_auth.app_credential_env', label: 'Application credential env vars', template: qOr('GOOGLE_APPLICATION_CREDENTIALS', 'DOCKER_AUTH_CONFIG') },
      { id: 'code.credentials_auth.cer_certificates', label: 'CER certificate files', template: q('extension:cer') },
      { id: 'code.credentials_auth.onepassword_token', label: '1Password service account token', template: q('"ops_eyJ"') },
      { id: 'code.credentials_auth.base64_secret_prefixes', label: 'Base64-encoded secret prefixes', template: qOr('"QUtJQ"', '"c2stb"', '"eG94"') },
    ],
  },
  {
    id: 'cloud_infra',
    target: 'code',
    name: 'Cloud Infrastructure',
    description: 'AWS, Azure, GCP, Firebase and PaaS provider keys, service accounts and storage credentials.',
    queries: [
      { id: 'code.cloud_infra.aws_key_prefixes', label: 'AWS access key prefixes', template: qOr('AKIA', 'ASIA', 'AROA', 'aws_secret', 'AWS_SECRET_ACCESS_KEY') },
      { id: 'code.cloud_infra.google_firebase_keys', label: 'Google & Firebase API keys', template: qOr('GOOGLE_API_KEY', 'AIza', 'FIREBASE_API_KEY') },
      { id: 'code.cloud_infra.azure_keys', label: 'Azure storage & client secrets', template: qOr('AZURE_STORAGE_KEY', 'DefaultEndpointsProtocol', 'azure_client_secret') },
      { id: 'code.cloud_infra.heroku', label: 'Heroku API keys', template: qOr('HEROKU_API_KEY', 'heroku') },
      { id: 'code.cloud_infra.vercel_netlify', label: 'Vercel & Netlify tokens', template: qOr('VERCEL_TOKEN', 'NETLIFY_TOKEN') },
      { id: 'code.cloud_infra.cloud_storage_access_keys', label: 'CDN & object storage access keys', template: qOr('cloudflare access_key', 'cloudfront access_key', 's3 access_key', 'azure_blob access_key', 'gcs access_key') },
      { id: 'code.cloud_infra.cloud_storage_secrets', label: 'CDN & object storage secrets', template: qOr('cloudflare secret', 'cloudfront secret', 's3 secret', 'azure_blob secret', 'gcs secret') },
      { id: 'code.cloud_infra.s3_buckets', label: 'S3 buckets & amazonaws hostnames', template: qOr('s3', 'bucket', 'amazonaws') },
      { id: 'code.cloud_infra.gcp_service_account_files', label: 'GCP service account JSON files', template: qOr('filename:service-account.json', 'filename:gcloud.json') },
      { id: 'code.cloud_infra.gcp_service_account_email', label: 'GCP service account addresses', template: q('gserviceaccount') },
      { id: 'code.cloud_infra.firebase_config_files', label: 'Firebase config files', template: qOr('filename:firebase.json', 'filename:.firebaserc') },
      { id: 'code.cloud_infra.firebase_tokens', label: 'Firebase API keys & tokens', template: qOr('FIREBASE_API_KEY', 'firebase_token') },
      { id: 'code.cloud_infra.aws_credentials_files', label: 'AWS credentials files', template: qOr('filename:.aws/credentials aws_access_key_id', 'filename:credentials aws_access_key_id') },
      { id: 'code.cloud_infra.firebase_client_config', label: 'Firebase client config (leaked in frontend)', template: qOr('firebase apiKey', 'firebase authDomain', 'firebase databaseURL') },
      { id: 'code.cloud_infra.cloudinary', label: 'Cloudinary credentials', template: qOr('cloudinary', 'cloud_name', 'CLOUDINARY_URL') },
      { id: 'code.cloud_infra.aws_bedrock', label: 'AWS Bedrock API keys', template: qOr('ABSK', 'bedrock-api-key', 'amazon bedrock') },
      { id: 'code.cloud_infra.heroku_tokens', label: 'Heroku token prefix (HRKU-)', template: qOr('HRKU-', 'heroku api') },
      { id: 'code.cloud_infra.vercel_token_prefixes', label: 'Vercel token prefixes', template: qOr('vck_', 'vca_', 'vcr_', 'vci_', 'vcp_') },
      { id: 'code.cloud_infra.infracost', label: 'Infracost API keys', template: qOr('ico-', 'infracost') },
      { id: 'code.cloud_infra.openshift', label: 'OpenShift tokens', template: qOr('sha256~', 'openshift') },
      { id: 'code.cloud_infra.prefect', label: 'Prefect API keys', template: qOr('pnu_', 'prefect') },
      { id: 'code.cloud_infra.scalingo', label: 'Scalingo tokens', template: qOr('tk-us-', 'scalingo') },
      { id: 'code.cloud_infra.digitalocean', label: 'DigitalOcean tokens', template: qOr('digitalocean', 'doo_v1_', 'dop_v1_', 'dor_v1_') },
      { id: 'code.cloud_infra.flyio', label: 'Fly.io tokens', template: qOr('flyio', 'fo1_', 'fm1', 'fm2_') },
      { id: 'code.cloud_infra.alibaba_fastly_misc', label: 'Alibaba, Fastly & misc provider keys', template: qOr('ltai', 'fastly', 'freemius', 'intra42', 's-s4t2') },
    ],
  },
  {
    id: 'database_storage',
    target: 'code',
    name: 'Database & Storage',
    description: 'Connection strings, database passwords and data platform credentials.',
    queries: [
      { id: 'code.database_storage.sql_nosql_engines', label: 'PostgreSQL / MySQL / MongoDB', template: qOr('postgresql', 'mysql', 'mongodb') },
      { id: 'code.database_storage.connection_strings', label: 'Redis & DATABASE_URL connection strings', template: qOr('redis', 'DATABASE_URL', 'connection_string') },
      { id: 'code.database_storage.mongo_redis_uris', label: 'Mongo & Redis URIs', template: qOr('MONGO_URI', 'MONGO_PASSWORD', 'REDIS_URL') },
      { id: 'code.database_storage.redis_elastic_credentials', label: 'Redis & Elasticsearch credentials', template: qOr('REDIS_PASSWORD', 'ELASTICSEARCH_URL', 'ELASTIC_PASSWORD') },
      { id: 'code.database_storage.db_config_files', label: 'Database config files with passwords', template: qOr('filename:elasticsearch.yml password', 'filename:mongo.conf password', 'filename:redis.conf password', 'filename:mongodb.yml password', 'filename:.pgpass password') },
      { id: 'code.database_storage.neo4j', label: 'Neo4j connection strings', template: qOr('neo4j', 'neo4j+s://', 'NEO4J_URI') },
      { id: 'code.database_storage.sqlserver_oledb', label: 'SQL Server / OLEDB connection strings', template: qOr('sqlserver', 'sqloledb', '"Data Source=" password') },
      { id: 'code.database_storage.db_client_configs', label: 'DBeaver & Robo3T saved connections', template: qOr('filename:dbeaver-data-sources.xml', 'filename:robomongo.json', 'filename:robo3t.json') },
      { id: 'code.database_storage.data_platforms', label: 'Data & speech platform keys', template: qOr('assemblyai', 'clickhouse', 'confluent', 'databricks', 'deepgram') },
      { id: 'code.database_storage.hashicorp_planetscale', label: 'HashiCorp & PlanetScale tokens', template: qOr('hashicorp', 'atlasv1', 'planetscale', 'pscale') },
    ],
  },
  {
    id: 'devops_cicd',
    target: 'code',
    name: 'DevOps & CI/CD',
    description: 'Source control tokens, package publishing tokens and CI pipeline secrets.',
    queries: [
      { id: 'code.devops_cicd.github_token_prefixes', label: 'GitHub token prefixes (ghp_ / gho_ / …)', template: qOr('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_') },
      { id: 'code.devops_cicd.gitlab_bitbucket_tokens', label: 'GitLab & Bitbucket tokens', template: qOr('glpat', 'BITBUCKET_APP_PASSWORD') },
      { id: 'code.devops_cicd.npm_tokens', label: 'npm tokens', template: qOr('npm_', 'npmrc', 'NPM_TOKEN') },
      { id: 'code.devops_cicd.docker_auth', label: 'Docker registry auth', template: qOr('_authToken', 'DOCKER_PASSWORD', 'docker_token') },
      { id: 'code.devops_cicd.ci_files_secret', label: 'CI pipeline files containing "secret"', template: qOr('filename:workflows secret', 'filename:.gitlab-ci.yml secret', 'filename:Jenkinsfile secret') },
      { id: 'code.devops_cicd.ci_files_token', label: 'CI pipeline files containing "token"', template: qOr('filename:workflows token', 'filename:.gitlab-ci.yml token', 'filename:Jenkinsfile token') },
      { id: 'code.devops_cicd.ci_config_files', label: 'Travis / Circle / Bitbucket pipeline files', template: qOr('filename:.travis.yml', 'filename:circle.yml', 'filename:bitbucket-pipelines.yml') },
      { id: 'code.devops_cicd.jenkins_buildkite', label: 'Jenkins & Buildkite tokens', template: qOr('JENKINS_API_TOKEN', 'JENKINS_PASSWORD', 'buildkite') },
      { id: 'code.devops_cicd.jenkins_config', label: 'jenkins.yml config files', template: q('filename:jenkins.yml') },
      { id: 'code.devops_cicd.sourcegraph', label: 'Sourcegraph tokens', template: qOr('sgp_', 'sourcegraph') },
      { id: 'code.devops_cicd.gitlab_ci_deploy_tokens', label: 'GitLab CI & deploy tokens', template: qOr('glcbt-', 'gldt-', 'glffct-') },
      { id: 'code.devops_cicd.gitlab_feature_oauth_tokens', label: 'GitLab feature flag & OAuth tokens', template: qOr('glft-', 'gloas-', 'glsoat-') },
      { id: 'code.devops_cicd.clojars', label: 'Clojars deploy tokens', template: qOr('CLOJARS_', 'clojars') },
      { id: 'code.devops_cicd.harness', label: 'Harness platform tokens', template: qOr('harness', 'pat.', 'sat.') },
      { id: 'code.devops_cicd.snyk', label: 'Snyk tokens', template: qOr('snyk_token', 'SNYK_TOKEN') },
      { id: 'code.devops_cicd.security_scanners', label: 'Drone CI, Endor Labs & Snyk', template: qOr('droneci', 'endorlabs', 'snyk') },
    ],
  },
  {
    id: 'iac',
    target: 'code',
    name: 'Infrastructure as Code',
    description: 'Terraform, Ansible, Docker Compose and Kubernetes manifests holding secrets.',
    queries: [
      { id: 'code.iac.terraform_secret', label: 'Terraform files containing "secret"', template: qOr('filename:terraform.tfvars secret', 'filename:variables.tf secret', 'filename:main.tf secret') },
      { id: 'code.iac.terraform_password', label: 'Terraform files containing "password"', template: qOr('filename:terraform.tfvars password', 'filename:variables.tf password', 'filename:main.tf password') },
      { id: 'code.iac.compose_k8s_files', label: 'Docker Compose & Kubernetes files', template: qOr('filename:docker-compose', 'filename:kubernetes') },
      { id: 'code.iac.k8s_image_pull_secrets', label: 'Kubernetes image pull secrets', template: qOr('imagePullSecrets', 'dockerconfigjson') },
      { id: 'code.iac.ansible_files', label: 'Ansible playbooks', template: qOr('filename:ansible', 'filename:playbook.yml') },
      { id: 'code.iac.ansible_vault', label: 'Ansible Vault', template: q('ansible_vault') },
      { id: 'code.iac.kube_configs', label: 'kubeconfig & secrets.yaml files', template: qOr('filename:.kube/config', 'filename:kubeconfig', 'filename:secrets.yaml') },
      { id: 'code.iac.kubernetes_keywords', label: 'kubectl / kubernetes keywords', template: qOr('kubectl', 'kubernetes') },
    ],
  },
  {
    id: 'config_files',
    target: 'code',
    name: 'Config & Secret Files',
    description: '.env files, framework config, appsettings and system credential stores.',
    queries: [
      { id: 'code.config_files.dotenv_secrets', label: '.env files with SECRET / KEY / TOKEN / PASSWORD', template: qOr('filename:.env SECRET', 'filename:.env KEY', 'filename:.env TOKEN', 'filename:.env PASSWORD') },
      { id: 'code.config_files.dotenv_variants', label: '.env.production / .staging / .local / .test', template: qOr('filename:.env.production', 'filename:.env.staging', 'filename:.env.local', 'filename:.env.test') },
      { id: 'code.config_files.app_config_password', label: 'App config files containing "password"', template: qOr('filename:config.yml password', 'filename:config.yaml password', 'filename:settings.py password', 'filename:application.properties password') },
      { id: 'code.config_files.app_config_secret', label: 'App config files containing "secret"', template: qOr('filename:config.yml secret', 'filename:config.yaml secret', 'filename:settings.py secret', 'filename:application.properties secret') },
      { id: 'code.config_files.web_app_configs', label: 'Web app configs (wp-config / web.config / .htpasswd)', template: qOr('filename:wp-config.php', 'filename:.htpasswd', 'filename:web.config', 'filename:configuration.php') },
      { id: 'code.config_files.mobile_service_configs', label: 'Mobile Google service configs', template: qOr('filename:GoogleService-Info.plist', 'filename:google-services.json') },
      { id: 'code.config_files.env_extension', label: '.env extension with secret keywords', template: qOr('extension:env password', 'extension:env secret', 'extension:env token', 'extension:env key') },
      { id: 'code.config_files.app_config_json_password', label: 'JSON/YAML app configs containing "password"', template: qOr('filename:config.json password', 'filename:database.yml password', 'filename:appsettings.json password', 'filename:settings.json password') },
      { id: 'code.config_files.app_config_json_secret', label: 'JSON/YAML app configs containing "secret"', template: qOr('filename:config.json secret', 'filename:database.yml secret', 'filename:appsettings.json secret', 'filename:settings.json secret') },
      { id: 'code.config_files.structured_api_key', label: 'JSON/YAML/INI files with api_key', template: qOr('extension:json api_key', 'extension:yml api_key', 'extension:ini api_key', 'extension:yaml api_key') },
      { id: 'code.config_files.structured_password', label: 'JSON/YAML/INI files with password', template: qOr('extension:json password', 'extension:yml password', 'extension:ini password', 'extension:yaml password') },
      { id: 'code.config_files.conf_xml_password', label: 'CONF / CFG / XML files with password', template: qOr('extension:conf password', 'extension:cfg password', 'extension:xml password') },
      { id: 'code.config_files.shell_rc_files', label: 'Shell rc files with secrets', template: qOr('filename:.bash_profile password', 'filename:.bash_profile secret', 'filename:.bashrc password', 'filename:.bashrc secret') },
      { id: 'code.config_files.framework_secret_files', label: 'Framework secret files (Rails / Phoenix / WP)', template: qOr('filename:secrets.yml', 'filename:master.key', 'filename:prod.secret.exs', 'filename:prod.exs', 'filename:wp-config.php') },
      { id: 'code.config_files.system_credential_stores', label: 'System & browser credential stores', template: qOr('filename:logins.json', 'filename:shadow', 'filename:passwd path:etc', 'filename:sshd_config') },
    ],
  },
  {
    id: 'backups_history',
    target: 'code',
    name: 'Backups, Dumps & Shell History',
    description: 'Database dumps, backup files, debug logs and shell history that leaks commands with secrets.',
    queries: [
      { id: 'code.backups_history.sql_dumps', label: 'SQL dumps & backup files', template: qOr('filename:.sql', 'filename:.dump', 'filename:backup') },
      { id: 'code.backups_history.backup_extensions', label: 'Backup extensions (.bak / .old)', template: qOr('filename:.bak', 'extension:old', 'extension:backup') },
      { id: 'code.backups_history.git_credential_files', label: 'Git credential files', template: qOr('filename:.git-credentials', 'filename:.gitconfig', 'filename:.github_credentials') },
      { id: 'code.backups_history.git_credential_helper', label: 'Git credential.helper config', template: q('credential.helper') },
      { id: 'code.backups_history.debug_logs', label: 'Debug & trace log files', template: qOr('debug extension:log', 'trace extension:log', 'verbose extension:log') },
      { id: 'code.backups_history.shell_history', label: 'Shell history files', template: qOr('filename:.bash_history', 'filename:.zsh_history', 'filename:.sh_history', 'filename:.mysql_history') },
      { id: 'code.backups_history.dotfile_credentials', label: 'Dotfile credential stores (.npmrc / .netrc)', template: qOr('filename:.npmrc', 'filename:.pypirc', 'filename:.netrc', 'filename:.gem/credentials') },
      { id: 'code.backups_history.sql_password_dump', label: 'SQL files with passwords or dumps', template: qOr('extension:sql password', 'extension:sql dump') },
      { id: 'code.backups_history.recovery_codes', label: 'Account recovery & backup codes', template: qOr('filename:github-recovery-codes.txt', 'filename:gitlab-recovery-codes.txt', 'filename:discord_backup_codes.txt') },
    ],
  },
  {
    id: 'secret_managers',
    target: 'code',
    name: 'Secret Managers & Vaults',
    description: 'HashiCorp Vault and Doppler tokens that unlock entire secret stores.',
    queries: [
      { id: 'code.secret_managers.vault_doppler_tokens', label: 'Vault & Doppler tokens', template: qOr('vault_token', 'VAULT_ADDR', 'hvs.', 'doppler_token') },
      { id: 'code.secret_managers.vault_token_file', label: '.vault-token files', template: q('filename:.vault-token') },
    ],
  },
  {
    id: 'package_registries',
    target: 'code',
    name: 'Package Registries & Artifacts',
    description: 'Artifactory, PyPI, RubyGems and NuGet publishing credentials.',
    queries: [
      { id: 'code.package_registries.artifactory_jfrog', label: 'Artifactory & JFrog tokens', template: qOr('artifactory', 'jfrog', 'AKCp', 'pip.conf') },
      { id: 'code.package_registries.pypirc', label: '.pypirc files', template: q('filename:.pypirc') },
      { id: 'code.package_registries.rapidapi_rubygems', label: 'RapidAPI, RubyGems & Sidekiq', template: qOr('rapidapi', 'rubygems', 'sidekiq') },
      { id: 'code.package_registries.misc_utilities', label: 'curl / PKCS12 / NuGet artifacts', template: qOr('curl', 'pkcs12', 'nuget') },
    ],
  },
  {
    id: 'payment_fintech',
    target: 'code',
    name: 'Payment & Fintech',
    description: 'Payment processors, crypto exchanges, shipping and banking API keys.',
    queries: [
      { id: 'code.payment_fintech.stripe_paypal', label: 'Stripe & PayPal live keys', template: qOr('sk_live', 'pk_live', 'stripe', 'paypal') },
      { id: 'code.payment_fintech.braintree_square', label: 'Braintree & Square tokens', template: qOr('braintree', 'sq0', 'SQUARE_ACCESS_TOKEN') },
      { id: 'code.payment_fintech.paypal_live_api', label: 'PayPal live API credentials', template: qOr('PAYPAL_LIVE_API_PASSWORD', 'PAYPAL_LIVE_API_USERNAME') },
      { id: 'code.payment_fintech.flutterwave', label: 'Flutterwave keys', template: qOr('FLWSECK_TEST', 'FLWPUBK_TEST', 'flutterwave') },
      { id: 'code.payment_fintech.plaid', label: 'Plaid credentials', template: qOr('plaid', 'PLAID_SECRET', 'PLAID_CLIENT_ID') },
      { id: 'code.payment_fintech.duffel', label: 'Duffel API keys', template: qOr('duffel_test', 'duffel_live') },
      { id: 'code.payment_fintech.easypost', label: 'EasyPost API keys', template: qOr('EZAK', 'EZTK', 'easypost') },
      { id: 'code.payment_fintech.shippo', label: 'Shippo API keys', template: qOr('shippo_live', 'shippo_test') },
      { id: 'code.payment_fintech.settlemint', label: 'SettleMint tokens', template: qOr('sm_aat_', 'sm_pat_', 'sm_sat_', 'settlemint') },
      { id: 'code.payment_fintech.crypto_exchanges', label: 'Crypto exchange API keys', template: qOr('coinbase', 'bittrex', 'kraken', 'kucoin') },
      { id: 'code.payment_fintech.finance_ecommerce', label: 'Finance & e-commerce platform keys', template: qOr('finicity', 'finnhub', 'freshbooks', 'shopify') },
    ],
  },
  {
    id: 'comms_saas',
    target: 'code',
    name: 'Communication & SaaS',
    description: 'Slack, email delivery, helpdesk, Atlassian and social platform tokens.',
    queries: [
      { id: 'code.comms_saas.slack_tokens', label: 'Slack bot & user tokens', template: qOr('xoxb', 'xoxp', 'SLACK_WEBHOOK', 'SLACK_TOKEN') },
      { id: 'code.comms_saas.email_providers', label: 'SendGrid, Mailgun & SMTP credentials', template: qOr('SG.', 'sendgrid', 'SENDGRID_API_KEY', 'mailgun', 'SMTP_PASSWORD') },
      { id: 'code.comms_saas.twilio_discord', label: 'Twilio & Discord tokens', template: qOr('twilio', 'TWILIO_AUTH_TOKEN', 'discord', 'slack_webhook') },
      { id: 'code.comms_saas.atlassian_suite', label: 'Atlassian, Jira, Trello & Confluence', template: qOr('atlassian.net', 'jira', 'trello.com', 'confluence') },
      { id: 'code.comms_saas.mailchimp', label: 'Mailchimp API keys', template: qOr('mailchimp', 'mailchimp_api_key') },
      { id: 'code.comms_saas.messaging_search_services', label: 'MessageBird, OneSignal & Algolia', template: qOr('messagebird', 'onesignal', 'algolia_admin_key') },
      { id: 'code.comms_saas.helpdesk_tokens', label: 'Zendesk & Freshdesk tokens', template: qOr('zendesk_token', 'freshdesk_key', 'freshdesk_api_key') },
      { id: 'code.comms_saas.atlassian_api_tokens', label: 'Atlassian API token prefix (ATATT3)', template: qOr('ATATT3', 'atlassian api_token') },
      { id: 'code.comms_saas.mapbox', label: 'Mapbox access tokens', template: qOr('mapbox', 'pk.eyJ', 'MAPBOX_ACCESS_TOKEN') },
      { id: 'code.comms_saas.teams_webhooks', label: 'Microsoft Teams webhooks', template: qOr('outlook.office.com/webhook', 'teams webhook') },
      { id: 'code.comms_saas.slack_legacy_tokens', label: 'Slack config & legacy tokens', template: qOr('xoxe.xox', 'xoxe-', 'xox[ar]-') },
      { id: 'code.comms_saas.collaboration_platforms', label: 'Asana, Contentful, Intercom & Mattermost', template: qOr('asana', 'beamer', 'contentful', 'intercom', 'mattermost') },
      { id: 'code.comms_saas.support_social_platforms', label: 'Zendesk, Facebook & Flickr', template: qOr('zendesk', 'facebook', 'eaam', 'eaac', 'flickr') },
      { id: 'code.comms_saas.social_messaging_platforms', label: 'LinkedIn, Sendbird & Sendinblue', template: qOr('linkedin', 'webhook.office.com', 'sendbird', 'sendinblue') },
      { id: 'code.comms_saas.social_media_platforms', label: 'Telegram, Twitch & Twitter', template: qOr('telegram', 'twitch', 'twitter') },
      { id: 'code.comms_saas.saas_platforms', label: 'Meraki, Dropbox, Etsy, HubSpot & Looker', template: qOr('cisco meraki', 'dropbox', 'etsy', 'hubspot', 'looker') },
      { id: 'code.comms_saas.data_content_services', label: 'MaxMind, Notion, NYTimes & Ollama', template: qOr('maxmind', 'notion', 'ntn_', 'nytimes', 'ollama') },
    ],
  },
  {
    id: 'ai_ml',
    target: 'code',
    name: 'AI & Machine Learning',
    description: 'LLM provider and ML platform API keys.',
    queries: [
      { id: 'code.ai_ml.llm_api_keys', label: 'OpenAI / Anthropic / HuggingFace api_key', template: qOr('openai api_key', 'anthropic api_key', 'claude api_key', 'huggingface api_key') },
      { id: 'code.ai_ml.llm_tokens', label: 'OpenAI / Anthropic / HuggingFace tokens', template: qOr('openai token', 'anthropic token', 'claude token', 'huggingface token') },
      { id: 'code.ai_ml.groq', label: 'Groq API keys', template: qOr('gsk_', 'GROQ_API_KEY', 'groq') },
      { id: 'code.ai_ml.xai', label: 'xAI API keys', template: qOr('xai-', 'XAI_API_KEY') },
      { id: 'code.ai_ml.nvidia', label: 'NVIDIA API keys', template: qOr('nvapi-', 'NVIDIA_API_KEY') },
      { id: 'code.ai_ml.openrouter', label: 'OpenRouter API keys', template: qOr('sk-or-v1-', 'OPENROUTER_API_KEY', 'openrouter') },
      { id: 'code.ai_ml.mistral', label: 'Mistral API keys', template: qOr('MISTRAL_API_KEY', 'mistral api') },
      { id: 'code.ai_ml.deepseek', label: 'DeepSeek API keys', template: qOr('DEEPSEEK_API_KEY', 'deepseek api') },
      { id: 'code.ai_ml.cerebras', label: 'Cerebras API keys', template: qOr('CEREBRAS_API_KEY', 'csk-') },
      { id: 'code.ai_ml.stability', label: 'Stability AI keys', template: qOr('STABILITY_API_KEY', 'stability ai') },
      { id: 'code.ai_ml.weights_biases', label: 'Weights & Biases API keys', template: qOr('wandb', 'WANDB_API_KEY', 'weights biases') },
      { id: 'code.ai_ml.elevenlabs', label: 'ElevenLabs API keys', template: qOr('elevenlabs', 'ELEVENLABS_API_KEY') },
      { id: 'code.ai_ml.cohere', label: 'Cohere API keys', template: qOr('cohere', 'CO_API_KEY') },
      { id: 'code.ai_ml.togetherai', label: 'Together AI keys', template: qOr('togetherai', 'tgp_v1_') },
    ],
  },
  {
    id: 'monitoring',
    target: 'code',
    name: 'Monitoring & Observability',
    description: 'APM, logging, error tracking and analytics platform keys.',
    queries: [
      { id: 'code.monitoring.observability_api_keys', label: 'Datadog / New Relic / Splunk api_key', template: qOr('datadog api_key', 'newrelic api_key', 'splunk api_key', 'elasticsearch api_key', 'grafana api_key') },
      { id: 'code.monitoring.observability_tokens', label: 'Datadog / New Relic / Splunk tokens', template: qOr('datadog token', 'newrelic token', 'splunk token', 'elasticsearch token', 'grafana token') },
      { id: 'code.monitoring.sentry_dynatrace', label: 'Sentry DSN & Dynatrace tokens', template: qOr('sentry_dsn', 'SENTRY_AUTH_TOKEN', 'dynatrace') },
      { id: 'code.monitoring.grafana_config', label: 'grafana.ini config files', template: q('filename:grafana.ini') },
      { id: 'code.monitoring.rollbar_sumologic_codecov', label: 'Rollbar, Sumo Logic & Codecov tokens', template: qOr('rollbar_access_token', 'sumologic', 'codecov_token') },
      { id: 'code.monitoring.posthog', label: 'PostHog API keys', template: qOr('posthog', 'phx_', 'phc_', 'POSTHOG_API_KEY') },
      { id: 'code.monitoring.sentry_user_tokens', label: 'Sentry user tokens (sntryu_)', template: qOr('sntryu_', 'sentry user') },
    ],
  },
  {
    id: 'internal_recon',
    target: 'code',
    name: 'Internal Infra & Recon',
    description: 'Internal hostnames, VPN configs, admin panels, IDE workspaces and scan artifacts.',
    queries: [
      { id: 'code.internal_recon.internal_assets', label: 'Internal keys, tokens & passwords', template: qOr('internal key', 'internal token', 'internal password') },
      { id: 'code.internal_recon.staging_assets', label: 'Staging keys, tokens & passwords', template: qOr('staging key', 'staging token', 'staging password') },
      { id: 'code.internal_recon.vpn_credentials', label: 'VPN keys, configs & passwords', template: qOr('vpn key', 'vpn config', 'vpn password') },
      { id: 'code.internal_recon.vpn_configs', label: 'WireGuard / OpenVPN / IPsec configs', template: qOr('wireguard config', 'openvpn config', 'ipsec config') },
      { id: 'code.internal_recon.admin_access', label: 'Admin passwords, tokens & URLs', template: qOr('admin password', 'admin token', 'admin url') },
      { id: 'code.internal_recon.portal_passwords', label: 'Dashboard / console / portal passwords', template: qOr('dashboard password', 'console password', 'portal password') },
      { id: 'code.internal_recon.api_specs', label: 'Swagger & OpenAPI specs', template: qOr('swagger api', 'openapi api') },
      { id: 'code.internal_recon.postman', label: 'Postman collections', template: qOr('postman api', 'postman collection') },
      { id: 'code.internal_recon.ftp_passwords', label: 'FTP & SFTP passwords', template: qOr('ftp_password', 'sftp_password') },
      { id: 'code.internal_recon.ftp_config_files', label: 'FTP config files', template: qOr('filename:.ftpconfig', 'filename:ftp.json') },
      { id: 'code.internal_recon.server_config_files', label: 'ProFTPD, DHCP & server configs', template: qOr('filename:proftpdpasswd', 'filename:dhcpd.conf', 'filename:server.cfg') },
      { id: 'code.internal_recon.ide_workspace_files', label: 'IDE workspace & settings files', template: qOr('path:.vscode filename:settings.json', 'path:.idea filename:workspace.xml', 'filename:vim_settings.xml') },
      { id: 'code.internal_recon.remote_access_configs', label: 'ngrok, Vagrant, RDP & ICA configs', template: qOr('filename:ngrok.yml', 'filename:Vagrantfile password', 'extension:rdp', 'extension:ica') },
      { id: 'code.internal_recon.nmap_scans', label: 'Nmap scan output files', template: qOr('extension:nmap', 'extension:gnmap') },
      { id: 'code.internal_recon.dangerous_php_functions', label: 'Dangerous PHP functions (webshell / RCE)', template: qOr('shell_exec', '"system("', '"eval("', '"passthru("') },
      { id: 'code.internal_recon.admin_panels', label: 'Admin panels, install & setup scripts', template: qOr('wp-admin', '"admin/login"', 'filename:install.php', 'filename:setup.sh') },
      { id: 'code.internal_recon.internal_docs', label: 'Internal docs, Swagger & preprod hosts', template: qOr('swagger', '"internal-docs"', 'preprod') },
      { id: 'code.internal_recon.sftp_client_configs', label: 'SFTP client & remote-sync configs', template: qOr('filename:sftp-config.json', 'filename:.remote-sync.json', 'filename:sftp.json', 'filename:filezilla.xml') },
      { id: 'code.internal_recon.server_list_configs', label: 'Saved server lists (FileZilla / WebServers)', template: qOr('filename:recentservers.xml', 'filename:WebServers.xml', 'filename:.ftpconfig', 'filename:ftp.json') },
    ],
  },
  {
    id: 'other_services',
    target: 'code',
    name: 'Other Services',
    description: 'License keys and remaining third-party vendor tokens.',
    queries: [
      { id: 'code.other_services.license_keys', label: 'License & activation keys', template: qOr('license_key', 'activation_key', 'serial_number', 'product_key') },
      { id: 'code.other_services.pulumi_token', label: 'Pulumi tokens (pulumip-)', template: q('pulumip-') },
      { id: 'code.other_services.frameio', label: 'Frame.io tokens', template: qOr('fio-u-', 'frameio') },
      { id: 'code.other_services.developer_platforms', label: 'Authress, Cursor, Gitea & Gitter', template: qOr('authress', 'scauth_', 'cursor', 'gitea', 'gitter') },
      { id: 'code.other_services.product_dev_tools', label: 'Greptile, LaunchDarkly & Linear', template: qOr('greptile', 'launchdarkly', 'linear', 'lin_api_') },
      { id: 'code.other_services.misc_dev_services', label: 'ReadMe, Replicate, Sonar, Typeform & Yandex', template: qOr('readme', 'replicate', 'sonar', 'typeform', 'yandex') },
      { id: 'code.other_services.privateai_squarespace', label: 'Private AI & Squarespace', template: qOr('privateai', 'squarespace') },
      { id: 'code.other_services.assorted_vendors', label: 'Adafruit, Adobe, Airtable & Alibaba', template: qOr('adafruit', 'adobe', 'p8e-', 'airtable', 'alibaba') },
    ],
  },
];

// ===================================================================
// COMMIT SEARCH
// ===================================================================

const COMMIT_AREAS: QueryArea[] = [
  {
    id: 'domain_mentions',
    target: 'commits',
    name: 'Domain Mentions & Keywords',
    description: 'Commit messages that name the domain alongside credential keywords.',
    queries: [
      { id: 'commits.domain_mentions.any', label: 'Any commit mentioning the domain', template: '{domain}' },
      { id: 'commits.domain_mentions.password', label: 'Domain + password', template: '{domain} password' },
      { id: 'commits.domain_mentions.secret', label: 'Domain + secret', template: '{domain} secret' },
      { id: 'commits.domain_mentions.key', label: 'Domain + key', template: '{domain} key' },
      { id: 'commits.domain_mentions.token', label: 'Domain + token', template: '{domain} token' },
      { id: 'commits.domain_mentions.api_key', label: 'Domain + api key', template: '{domain} api key' },
    ],
  },
  {
    id: 'leak_signals',
    target: 'commits',
    name: 'Leak & Exposure Signals',
    description: 'Commits that acknowledge a leak or reverse a credential exposure.',
    queries: [
      { id: 'commits.leak_signals.remove', label: 'Remove domain', template: 'remove {domain}' },
      { id: 'commits.leak_signals.fix_credential', label: 'Fix domain credential', template: 'fix {domain} credential' },
      { id: 'commits.leak_signals.leak', label: 'Domain + leak', template: '{domain} leak' },
      { id: 'commits.leak_signals.exposed', label: 'Domain + exposed', template: '{domain} exposed' },
      { id: 'commits.leak_signals.security_fix', label: 'Domain + security fix', template: '{domain} security fix' },
      { id: 'commits.leak_signals.revert_credential', label: 'Revert domain credential', template: 'revert {domain} credential' },
    ],
  },
  {
    id: 'rotation',
    target: 'commits',
    name: 'Credential Rotation',
    description: 'Rotation and revocation commits — a strong signal the old secret is still in history.',
    queries: [
      { id: 'commits.rotation.rotate_key', label: 'Rotate key', template: '{domain} rotate key' },
      { id: 'commits.rotation.rotate_token', label: 'Rotate token', template: '{domain} rotate token' },
      { id: 'commits.rotation.rotate_secret', label: 'Rotate secret', template: '{domain} rotate secret' },
      { id: 'commits.rotation.regenerate', label: 'Regenerate', template: '{domain} regenerate' },
      { id: 'commits.rotation.revoke', label: 'Revoke', template: '{domain} revoke' },
    ],
  },
  {
    id: 'accidental',
    target: 'commits',
    name: 'Accidental Commit Signals',
    description: 'Phrases developers use when they realise they committed something they should not have.',
    queries: [
      { id: 'commits.accidental.accidentally', label: 'Accidentally', template: '{domain} accidentally' },
      { id: 'commits.accidental.should_not', label: 'Should not', template: '{domain} should not' },
      { id: 'commits.accidental.oops', label: 'Oops', template: '{domain} oops' },
    ],
  },
  {
    id: 'config_removal',
    target: 'commits',
    name: 'Config & .env Removal',
    description: 'Commits that pull config files out of the tree — the file usually survives in history.',
    queries: [
      { id: 'commits.config_removal.remove_env', label: 'Remove .env', template: '{domain} remove .env' },
      { id: 'commits.config_removal.remove_config', label: 'Remove config', template: '{domain} remove config' },
      { id: 'commits.config_removal.remove_credentials', label: 'Remove credentials', template: '{domain} remove credentials' },
      { id: 'commits.config_removal.gitignore', label: 'Gitignore', template: '{domain} gitignore' },
    ],
  },
  {
    id: 'service_specific',
    target: 'commits',
    name: 'Service-Specific',
    description: 'Commits naming a specific provider next to the domain.',
    queries: [
      { id: 'commits.service_specific.aws', label: 'Domain + AWS', template: '{domain} AWS' },
      { id: 'commits.service_specific.stripe', label: 'Domain + Stripe', template: '{domain} stripe' },
      { id: 'commits.service_specific.firebase', label: 'Domain + Firebase', template: '{domain} firebase' },
    ],
  },
  {
    id: 'remediation',
    target: 'commits',
    name: 'Remediation',
    description: 'Hotfix and patch commits that follow a credential incident.',
    queries: [
      { id: 'commits.remediation.hotfix_credential', label: 'Hotfix credential', template: '{domain} hotfix credential' },
      { id: 'commits.remediation.patch_secret', label: 'Patch secret', template: '{domain} patch secret' },
      { id: 'commits.remediation.update_password', label: 'Update password', template: '{domain} update password' },
    ],
  },
];

// ===================================================================
// ISSUE SEARCH
// ===================================================================

const ISSUE_AREAS: QueryArea[] = [
  {
    id: 'domain_mentions',
    target: 'issues',
    name: 'Domain Mentions & Credentials',
    description: 'Issues and pull requests that name the domain alongside credential keywords.',
    queries: [
      { id: 'issues.domain_mentions.any', label: 'Any issue mentioning the domain', template: '{domain}' },
      { id: 'issues.domain_mentions.credentials', label: 'Domain + credentials', template: '{domain} credentials' },
      { id: 'issues.domain_mentions.api_key', label: 'Domain + api key', template: '{domain} api key' },
      { id: 'issues.domain_mentions.password', label: 'Domain + password', template: '{domain} password' },
      { id: 'issues.domain_mentions.token', label: 'Domain + token', template: '{domain} token' },
      { id: 'issues.domain_mentions.secret_leaked', label: 'Domain + secret leaked', template: '{domain} secret leaked' },
      { id: 'issues.domain_mentions.config', label: 'Domain + config', template: '{domain} config' },
    ],
  },
  {
    id: 'vulnerability',
    target: 'issues',
    name: 'Vulnerability & Exposure',
    description: 'Issues reporting a vulnerability or an exposure affecting the domain.',
    queries: [
      { id: 'issues.vulnerability.vulnerability', label: 'Domain + vulnerability', template: '{domain} vulnerability' },
      { id: 'issues.vulnerability.exposed', label: 'Domain + exposed', template: '{domain} exposed' },
    ],
  },
  {
    id: 'help_seeking',
    target: 'issues',
    name: 'Help-Seeking & Errors',
    description: 'Users troubleshooting auth failures frequently paste real credentials.',
    queries: [
      { id: 'issues.help_seeking.not_working', label: 'Not working', template: '{domain} not working' },
      { id: 'issues.help_seeking.error_401', label: 'Error 401', template: '{domain} error 401' },
      { id: 'issues.help_seeking.error_403', label: 'Error 403', template: '{domain} error 403' },
      { id: 'issues.help_seeking.connection_refused', label: 'Connection refused', template: '{domain} connection refused' },
    ],
  },
  {
    id: 'logs_traces',
    target: 'issues',
    name: 'Logs & Stack Traces',
    description: 'Pasted logs and traces that carry tokens in headers or URLs.',
    queries: [
      { id: 'issues.logs_traces.stack_trace', label: 'Stack trace', template: '{domain} stack trace' },
      { id: 'issues.logs_traces.log_output', label: 'Log output', template: '{domain} log output' },
    ],
  },
  {
    id: 'configuration',
    target: 'issues',
    name: 'Configuration Discussion',
    description: 'Threads about environment variables and setup where config is pasted verbatim.',
    queries: [
      { id: 'issues.configuration.environment_variable', label: 'Environment variable', template: '{domain} environment variable' },
      { id: 'issues.configuration.dotenv', label: '.env', template: '{domain} .env' },
      { id: 'issues.configuration.setup_guide', label: 'Setup guide', template: '{domain} setup guide' },
    ],
  },
  {
    id: 'disclosure',
    target: 'issues',
    name: 'Security Disclosure',
    description: 'Public security reports and breach discussions naming the domain.',
    queries: [
      { id: 'issues.disclosure.security_issue', label: 'Security issue', template: '{domain} security issue' },
      { id: 'issues.disclosure.data_breach', label: 'Data breach', template: '{domain} data breach' },
      { id: 'issues.disclosure.responsible_disclosure', label: 'Responsible disclosure', template: '{domain} responsible disclosure' },
    ],
  },
  {
    id: 'access_auth',
    target: 'issues',
    name: 'Access & Authentication',
    description: 'Authentication and access-denied threads around the domain.',
    queries: [
      { id: 'issues.access_auth.authentication', label: 'Authentication', template: '{domain} authentication' },
      { id: 'issues.access_auth.login_failed', label: 'Login failed', template: '{domain} login failed' },
      { id: 'issues.access_auth.access_denied', label: 'Access denied', template: '{domain} access denied' },
    ],
  },
];

export const QUERY_CATALOG: QueryArea[] = [...CODE_AREAS, ...COMMIT_AREAS, ...ISSUE_AREAS];

export const ALL_QUERY_IDS: string[] = QUERY_CATALOG.flatMap(area => area.queries.map(query => query.id));

const QUERY_BY_ID = new Map<string, QueryDefinition>(
  QUERY_CATALOG.flatMap(area => area.queries.map(query => [query.id, query] as const))
);

/** Replace every `{domain}` placeholder with the scanned domain. */
export function renderQuery(template: string, domain: string): string {
  return template.split('{domain}').join(domain);
}

export function isKnownQueryId(id: string): boolean {
  return QUERY_BY_ID.has(id);
}

export function getAreasForTarget(target: QueryTarget): QueryArea[] {
  return QUERY_CATALOG.filter(area => area.target === target);
}
