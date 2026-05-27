import prisma from '../config/database';
import GitHubService, { SearchResult, CommitResult, IssueResult } from './github.service';
import {
  SECRET_PATTERNS,
  getDomainPatterns,
  calculateEntropy,
  extractContext,
  createPreview,
  isFalsePositive
} from '../utils/patterns';
import { calculateCriticalityScore, scoreToCriticality, calculateFileCriticalityScore } from './scoring.service';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * Scanner Service
 * Orchestrates the scanning process for a domain
 * Supports abort/cancel and real-time progress tracking with percentage
 */

interface ScanOptions {
  includeCode?: boolean;
  includeCommits?: boolean;
  includeIssues?: boolean;
}

interface ExtractedSecret {
  type: string;
  content: string;
  matchIndex: number;
}

// Global registry of active scans for cancellation
const activeScans = new Map<string, AbortController>();

// Total query counts for percentage calculation
const CODE_QUERIES_COUNT = 193; // Updated to match actual buildOptimizedQueries count
const COMMIT_QUERIES_COUNT = 30;
const ISSUE_QUERIES_COUNT = 24;
const TOTAL_STEPS = CODE_QUERIES_COUNT + COMMIT_QUERIES_COUNT + ISSUE_QUERIES_COUNT; // 247

class ScannerService {
  private githubService: GitHubService;

  constructor(githubToken: string) {
    this.githubService = new GitHubService(githubToken);
  }

  /**
   * Check if a scan is currently running
   */
  static isRunning(scanId: string): boolean {
    return activeScans.has(scanId);
  }

  /**
   * Get all active scan IDs
   */
  static getActiveScans(): string[] {
    return Array.from(activeScans.keys());
  }

  /**
   * Execute a full scan for a domain
   */
  async executeScan(scanId: string, domain: string, options: { includeCode?: boolean; includeCommits?: boolean; includeIssues?: boolean } = {}): Promise<void> {
    const {
      includeCode = true,
      includeCommits = true,
      includeIssues = true,
    } = options;

    // Create abort controller for this scan
    const abortController = new AbortController();
    activeScans.set(scanId, abortController);
    const signal = abortController.signal;

    // Track global step counter for percentage
    let completedSteps = 0;
    let lastProgressUpdate = 0;

    const updateProgress = async (phase: string, stepInPhase: number, totalInPhase: number, message: string, findingsCount: number) => {
      const percent = Math.round((completedSteps / TOTAL_STEPS) * 100);
      
      const now = Date.now();
      // Debounce database updates to prevent SQLite locking (update every 1s or if complete)
      if (now - lastProgressUpdate < 1000 && percent < 100) return;
      lastProgressUpdate = now;

      const progressData = JSON.stringify({
        percent,
        phase,
        step: stepInPhase,
        totalSteps: totalInPhase,
        message,
        findings: findingsCount
      });
      try {
        await prisma.scan.update({
          where: { id: scanId },
          data: { errorMessage: `PROGRESS:${progressData}` }
        });
      } catch (e) {
        // Non-critical
      }
    };

    try {
      // Update scan status to RUNNING
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'RUNNING',
          startedAt: new Date()
        }
      });

      logger.info(`Starting scan ${scanId} for domain: ${domain}`);

      // Build a regex that validates the domain is NOT preceded by a letter.
      // This filters out substring false positives (e.g. "mailexample.com" when scanning "example.com").
      // Allowed prefixes: start-of-string, digits, dots, slashes, @, etc.
      // Blocked prefix: any ASCII letter [a-zA-Z].
      const escapedDomainForRegex = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const domainValidationRegex = new RegExp(`(?<![a-zA-Z])${escapedDomainForRegex}`, 'i');

      const allRawFindings: any[] = [];
      const seenContentHashes = new Set<string>();

      // Cross-scan deduplication: pre-load content hashes of ALL existing secrets
      // for this domain so that re-scanning the same domain never creates duplicates.
      const existingSecrets = await prisma.secret.findMany({
        where: {
          finding: {
            scan: {
              domain: { name: domain },
              status: { in: ['COMPLETED', 'FAILED', 'CANCELLED'] }
            },
            NOT: { scanId }   // exclude the current scan (it's still RUNNING)
          }
        },
        select: { content: true, finding: { select: { repository: true, filePath: true } } }
      });
      for (const s of existingSecrets) {
        seenContentHashes.add(this.hashContent(s.content + s.finding.repository + s.finding.filePath));
      }
      logger.info(`Cross-scan dedup: pre-loaded ${existingSecrets.length} existing hashes for ${domain}`);

      const checkAbort = () => {
        if (signal.aborted) {
          throw new Error('SCAN_CANCELLED');
        }
      };

      // 1. Scan code repositories (steps 0..37)
      if (includeCode) {
        checkAbort();
        logger.info('Phase 1/3: Scanning code repositories...');
        const codeFindings = await this.scanCode(scanId, domain, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = step;
          await updateProgress('code', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...codeFindings);
        completedSteps = CODE_QUERIES_COUNT;
      }

      // 2. Scan commits (steps 38..44)
      if (includeCommits) {
        checkAbort();
        logger.info('Phase 2/3: Scanning commits...');
        const commitFindings = await this.scanCommits(scanId, domain, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = CODE_QUERIES_COUNT + step;
          await updateProgress('commits', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...commitFindings);
        completedSteps = CODE_QUERIES_COUNT + COMMIT_QUERIES_COUNT;
      }

      // 3. Scan issues (steps 45..50)
      if (includeIssues) {
        checkAbort();
        logger.info('Phase 3/3: Scanning issues...');
        const issueFindings = await this.scanIssues(scanId, domain, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = CODE_QUERIES_COUNT + COMMIT_QUERIES_COUNT + step;
          await updateProgress('issues', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...issueFindings);
        completedSteps = TOTAL_STEPS;
      }

      checkAbort();

      logger.info(`Scan ${scanId} found ${allRawFindings.length} unique findings`);

      // Count by criticality
      const counts = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0 };
      for (const f of allRawFindings) {
        switch (f.criticality) {
          case 'CRITICAL': counts.criticalCount++; break;
          case 'HIGH': counts.highCount++; break;
          case 'MEDIUM': counts.mediumCount++; break;
          case 'LOW': counts.lowCount++; break;
          case 'INFO': counts.infoCount++; break;
        }
      }

      // Update scan with results
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          completedAt: new Date(),
          totalFindings: allRawFindings.length,
          errorMessage: null,
          ...counts
        }
      });

      // Update domain last scan time
      const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { domain: true } });
      if (scan) {
        await prisma.domain.update({ where: { id: scan.domainId }, data: { lastScanAt: new Date() } });
      }

      logger.info(`Scan ${scanId} completed successfully`);
    } catch (error: any) {
      if (error.message === 'SCAN_CANCELLED') {
        logger.info(`Scan ${scanId} was cancelled by user`);
        await prisma.scan.update({
          where: { id: scanId },
          data: { status: 'CANCELLED', completedAt: new Date(), errorMessage: 'Scan cancelled by user' }
        });
        return;
      }

      const errorMessage = error.message || 'Unknown error occurred';
      const isGitHubError = error.status === 403 || error.status === 401 || error.status === 422;
      const detailedMessage = isGitHubError
        ? `GitHub API Error (${error.status}): ${errorMessage}. Please check your GitHub token and rate limits.`
        : `Scan Error: ${errorMessage}`;

      logger.error(`Scan ${scanId} failed:`, error);
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'FAILED', completedAt: new Date(), errorMessage: detailedMessage }
      });

      throw error;
    } finally {
      activeScans.delete(scanId);
    }
  }

  /**
   * Scan code repositories
   */
  private async scanCode(
    scanId: string,
    domain: string,
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const domainPatterns = getDomainPatterns(domain);
      const allPatterns = [...SECRET_PATTERNS, ...domainPatterns];
      const queries = this.buildOptimizedQueries(domain);

      let queryIndex = 0;
      let skippedQueries = 0;
      // Identify email-specific queries (GROUP 0) for multi-page fetching
      const emailQueryPrefix = `"@${domain}"`;
      for (const query of queries) {
        if (signal.aborted) break;
        queryIndex++;
        const shortQuery = query.length > 70 ? query.substring(0, 67) + '...' : query;
        await onProgress(queryIndex, queries.length, `Code: ${shortQuery}`);

        // All code queries get multi-page fetching up to GitHub's hard max (10 pages x 100 = 1000 results)
        const isEmailQuery = query.startsWith(emailQueryPrefix);
        const pagesToFetch = 10;
        const perPage = 100; // GitHub's maximum

        // Dual-query strategy: GitHub returns DIFFERENT results depending on fork qualifier.
        // - No qualifier: returns source repos + wikis but excludes forks
        // - fork:only: returns fork-exclusive repos
        // We run BOTH and merge by SHA to get maximum coverage.
        const queriesToRun = [query, `${query} fork:only`];
        const seenShas = new Set<string>();
        const allPageResults: any[] = [];

        for (const searchQuery of queriesToRun) {
          if (signal.aborted) break;
          for (let page = 1; page <= pagesToFetch; page++) {
            if (signal.aborted) break;
            try {
              const pageResults = await this.githubService.searchCode(searchQuery, {
                perPage,
                page
              });
              for (const result of pageResults) {
                if (!seenShas.has(result.sha)) {
                  seenShas.add(result.sha);
                  allPageResults.push(result);
                }
              }
              // If we got fewer results than perPage, no more pages to fetch
              if (pageResults.length < perPage) break;
            } catch (pageError: any) {
              if (pageError.status === 422) {
                logger.warn(`Query ${queryIndex}/${queries.length} skipped (GitHub 422 query parse error): ${searchQuery.substring(0, 80)}`);
                break; // Stop pagination on parse error
              }
              if (page === 1) {
                // On first page failure of fork:only variant, just skip it (source query already ran)
                if (searchQuery.includes('fork:only')) break;
                throw pageError;
              }
              break; // Silently stop pagination on later page errors
            }
          }
        }

        const results = allPageResults;
        try {
          logger.info(`Query ${queryIndex}/${queries.length}${isEmailQuery ? ' [EMAIL-MULTI-PAGE]' : ''} → ${results.length} results`);

          let resultCount = 0;
          for (const result of results) {
            if (signal.aborted) break;
            resultCount++;

            // Domain substring validation: skip files where the domain only appears
            // as part of a larger word (e.g. "mailexample.com" when scanning "example.com")
            // We check content, file path, and repository name
            if (!domainValidationRegex.test(result.content) &&
                !domainValidationRegex.test(result.repository) &&
                !domainValidationRegex.test(result.filePath)) {
              logger.debug(`Skipping code result ${result.repository}/${result.filePath} (domain substring mismatch)`);
              continue;
            }

            const secrets = this.extractSecrets(result.content, allPatterns);

            // Yield event loop every 20 files to prevent blocking the entire node process during heavy regex computations
            if (resultCount % 20 === 0) {
              await new Promise(resolve => setImmediate(resolve));
            }

            // Also detect credential pairs in code files
            const credentialPairs = this.detectCredentialPairs(result.content, domain);
            const allSecrets = [...secrets, ...credentialPairs];

            // Fetch file's last commit date only when secrets are found (saves API quota)
            let fileCommitDate: Date | undefined;
            if (allSecrets.length > 0) {
              fileCommitDate = await this.githubService.getFileLastCommitDate(result.repository, result.filePath);
            }

            const validSecrets = [];
            for (const secret of allSecrets) {
              const contentHash = this.hashContent(secret.content + result.repository + result.filePath);
              if (seenHashes.has(contentHash)) continue;
              seenHashes.add(contentHash);

              const context = extractContext(result.content, secret.matchIndex);
              if (secret.type !== 'CREDENTIAL_PAIR' && isFalsePositive(secret.content, context)) continue;

              const entropy = calculateEntropy(secret.content);

              let score: number;
              let criticality: string;

              if (secret.type === 'CREDENTIAL_PAIR') {
                score = 80;
                criticality = 'HIGH';
              } else if (secret.type === 'EMAIL' && credentialPairs.length > 0) {
                score = 55;
                criticality = 'MEDIUM';
              } else {
                score = calculateCriticalityScore({
                  type: secret.type, content: secret.content, context,
                  repository: result.repository, entropy
                });
                criticality = scoreToCriticality(score);
              }

              validSecrets.push({
                type: secret.type,
                content: secret.content,
                contentPreview: createPreview(secret.content),
                context,
                score,
                criticality
              });
            }

            if (validSecrets.length === 0) continue;

            const { score: fileScore, primaryType, criticality: fileCriticality } = calculateFileCriticalityScore(validSecrets);

            const finding = await prisma.finding.create({
              data: {
                scanId,
                repository: result.repository,
                repositoryUrl: result.repositoryUrl,
                filePath: result.filePath,
                fileUrl: result.htmlUrl,
                commitSha: result.commitSha,
                commitUrl: result.commitUrl,
                commitDate: fileCommitDate,
                score: fileScore,
                primaryType,
                criticality: fileCriticality,
                secrets: {
                  create: validSecrets.map(s => ({
                    type: s.type,
                    criticality: s.criticality,
                    content: s.content,
                    contentPreview: s.contentPreview,
                    context: s.context
                  }))
                }
              },
              include: { secrets: true }
            });
            findings.push(finding);
          }
        } catch (error: any) {
          if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
          // Skip GitHub API parsing errors (422) gracefully
          if (error.status === 422) {
            skippedQueries++;
            logger.warn(`Query ${queryIndex}/${queries.length} skipped (GitHub API 422 parsing error)`);
            continue;
          }
          logger.error(`Error processing query "${query.substring(0, 60)}":`, error);
        }
      }
    } catch (error: any) {
      if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
      logger.error('Error in scanCode:', error);
    }

    return findings;
  }

  /**
   * Build optimized queries using the repeated-domain OR format.
   *
   * GitHub REST API /search/code uses a legacy parser that rejects
   * "domain" (A OR B OR C) with 422 for many domains.
   * The universally compatible format is:
   *   "domain" A OR "domain" B OR "domain" C
   * 
   * GitHub Search limits enforced here:
   *   1. Maximum of 5 OR operators per query. Exceeding this causes a silent failure
   *      (returns 0 results without a 422 error).
   *   2. Never mix filename:/extension: qualifiers with plain terms in the same OR group.
   *   3. Never put "qualifier plain-term" as a single OR operand.
   */
  private buildOptimizedQueries(domain: string): string[] {
    const d = `"${domain}"`;
    // Simple query (no OR): "domain" extra
    const q = (extra: string) => `${d} ${extra}`;
    // Repeated-domain OR: "domain" A OR "domain" B OR "domain" C
    const qOr = (...terms: string[]) => terms.map(t => `${d} ${t}`).join(' OR ');
    const queries: string[] = [];

    // GROUP 0: EMAIL DISCOVERY — Direct @domain searches
    queries.push(`"@${domain}"`);
    queries.push(`"@${domain}" password OR "@${domain}" passwd OR "@${domain}" pwd OR "@${domain}" credentials OR "@${domain}" secret`);
    queries.push(`"@${domain}" username OR "@${domain}" login OR "@${domain}" account OR "@${domain}" user`);
    queries.push(`"@${domain}" email OR "@${domain}" contact OR "@${domain}" admin OR "@${domain}" info OR "@${domain}" support`);
    queries.push(`"@${domain}" token OR "@${domain}" api_key OR "@${domain}" apikey OR "@${domain}" key`);
    queries.push(`"@${domain}" extension:sql OR "@${domain}" extension:csv OR "@${domain}" extension:txt`);
    queries.push(`"@${domain}" extension:conf OR "@${domain}" extension:ini OR "@${domain}" extension:cfg OR "@${domain}" extension:yaml`);
    queries.push(`"@${domain}" filename:.env OR "@${domain}" filename:config OR "@${domain}" filename:settings`);

    // GROUP 1: High-value credential patterns
    queries.push(qOr('AKIA', 'ASIA', 'AROA', 'aws_secret', 'AWS_SECRET_ACCESS_KEY'));
    queries.push(qOr('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'));
    queries.push(qOr('glpat', 'BITBUCKET_APP_PASSWORD'));
    queries.push(qOr('"BEGIN PRIVATE KEY"', '"BEGIN RSA PRIVATE KEY"', '"BEGIN OPENSSH PRIVATE KEY"', '"BEGIN PGP PRIVATE KEY"'));

    // GROUP 2: Cloud & SaaS API keys
    queries.push(qOr('GOOGLE_API_KEY', 'AIza', 'FIREBASE_API_KEY'));
    queries.push(qOr('AZURE_STORAGE_KEY', 'DefaultEndpointsProtocol', 'azure_client_secret'));
    queries.push(qOr('api_key', 'apikey', 'API_KEY', 'api_secret'));

    // GROUP 3: Authentication & tokens
    queries.push(qOr('jwt_secret', 'JWT_SECRET', 'bearer'));
    queries.push(qOr('oauth_token', 'access_token', 'refresh_token'));
    queries.push(qOr('password', 'passwd', 'pwd', 'credentials'));

    // GROUP 4: Database credentials
    queries.push(qOr('postgresql', 'mysql', 'mongodb'));
    queries.push(qOr('redis', 'DATABASE_URL', 'connection_string'));

    // GROUP 5: Communication services
    queries.push(qOr('xoxb', 'xoxp', 'SLACK_WEBHOOK', 'SLACK_TOKEN'));
    queries.push(qOr('SG.', 'sendgrid', 'SENDGRID_API_KEY', 'mailgun', 'SMTP_PASSWORD'));
    queries.push(qOr('twilio', 'TWILIO_AUTH_TOKEN', 'discord', 'slack_webhook'));

    // GROUP 6: Payment providers
    queries.push(qOr('sk_live', 'pk_live', 'stripe', 'paypal'));
    queries.push(qOr('braintree', 'sq0', 'SQUARE_ACCESS_TOKEN'));

    // GROUP 7: DevOps & CI/CD
    queries.push(qOr('npm_', 'npmrc', 'NPM_TOKEN'));
    queries.push(qOr('_authToken', 'DOCKER_PASSWORD', 'docker_token'));
    queries.push(qOr('HEROKU_API_KEY', 'heroku'));
    queries.push(qOr('VERCEL_TOKEN', 'NETLIFY_TOKEN'));

    // GROUP 8: Configuration files with secrets
    queries.push(qOr('filename:.env SECRET', 'filename:.env KEY', 'filename:.env TOKEN', 'filename:.env PASSWORD'));
    queries.push(qOr('filename:.env.production', 'filename:.env.staging', 'filename:.env.local', 'filename:.env.test'));
    queries.push(qOr('filename:config.yml password', 'filename:config.yaml password', 'filename:settings.py password', 'filename:application.properties password'));
    queries.push(qOr('filename:config.yml secret', 'filename:config.yaml secret', 'filename:settings.py secret', 'filename:application.properties secret'));

    // GROUP 9: CI/CD pipeline files
    queries.push(qOr('filename:workflows secret', 'filename:.gitlab-ci.yml secret', 'filename:Jenkinsfile secret'));
    queries.push(qOr('filename:workflows token', 'filename:.gitlab-ci.yml token', 'filename:Jenkinsfile token'));
    queries.push(qOr('filename:.travis.yml', 'filename:circle.yml', 'filename:bitbucket-pipelines.yml'));

    // GROUP 10: Infrastructure as Code
    queries.push(qOr('filename:terraform.tfvars secret', 'filename:variables.tf secret', 'filename:main.tf secret'));
    queries.push(qOr('filename:terraform.tfvars password', 'filename:variables.tf password', 'filename:main.tf password'));
    queries.push(qOr('filename:docker-compose', 'filename:kubernetes'));
    queries.push(qOr('imagePullSecrets', 'dockerconfigjson'));
    queries.push(qOr('filename:ansible', 'filename:playbook.yml'));
    queries.push(q('ansible_vault'));

    // GROUP 11: Internal infrastructure exposure
    queries.push(qOr('internal key', 'internal token', 'internal password'));
    queries.push(qOr('staging key', 'staging token', 'staging password'));
    queries.push(qOr('vpn key', 'vpn config', 'vpn password'));
    queries.push(qOr('wireguard config', 'openvpn config', 'ipsec config'));
    queries.push(qOr('admin password', 'admin token', 'admin url'));
    queries.push(qOr('dashboard password', 'console password', 'portal password'));

    // GROUP 12: Web application secrets
    queries.push(qOr('filename:wp-config.php', 'filename:.htpasswd', 'filename:web.config', 'filename:configuration.php'));
    queries.push(qOr('filename:GoogleService-Info.plist', 'filename:google-services.json'));
    queries.push(qOr('swagger api', 'openapi api'));
    queries.push(qOr('postman api', 'postman collection'));

    // GROUP 13: Backup and dump files
    queries.push(qOr('filename:.sql', 'filename:.dump', 'filename:backup'));
    queries.push(qOr('filename:.bak', 'extension:old', 'extension:backup'));
    queries.push(qOr('filename:.git-credentials', 'filename:.gitconfig', 'filename:.github_credentials'));
    queries.push(q('credential.helper'));

    // GROUP 14: Monitoring & observability
    queries.push(qOr('datadog api_key', 'newrelic api_key', 'splunk api_key', 'elasticsearch api_key', 'grafana api_key'));
    queries.push(qOr('datadog token', 'newrelic token', 'splunk token', 'elasticsearch token', 'grafana token'));
    queries.push(qOr('cloudflare access_key', 'cloudfront access_key', 's3 access_key', 'azure_blob access_key', 'gcs access_key'));
    queries.push(qOr('cloudflare secret', 'cloudfront secret', 's3 secret', 'azure_blob secret', 'gcs secret'));

    // GROUP 15: AI/ML service keys
    queries.push(qOr('openai api_key', 'anthropic api_key', 'claude api_key', 'huggingface api_key'));
    queries.push(qOr('openai token', 'anthropic token', 'claude token', 'huggingface token'));

    // GROUP 16: License & activation
    queries.push(qOr('license_key', 'activation_key', 'serial_number', 'product_key'));

    // GROUP 17: S3 buckets and internal hostnames
    queries.push(qOr('s3', 'bucket', 'amazonaws'));

    // GROUP 18: SSH and deployment configs
    queries.push(qOr('ssh', 'deploy_key', 'id_rsa', 'known_hosts', 'authorized_keys'));

    // GROUP 19: Certificate files
    queries.push(qOr('filename:.pem', 'filename:.p12', 'filename:.pfx', 'filename:.key', 'filename:.crt'));

    // GROUP 20: Debug artifacts and logs
    queries.push(qOr('debug extension:log', 'trace extension:log', 'verbose extension:log'));

    // --- DEEP ANALYSIS GROUPS (14 tools + 3 dork files) ---

    // GROUP 21: Google Cloud & Service Accounts
    queries.push(qOr('filename:service-account.json', 'filename:gcloud.json'));
    queries.push(q('gserviceaccount'));
    queries.push(qOr('filename:firebase.json', 'filename:.firebaserc'));
    queries.push(qOr('FIREBASE_API_KEY', 'firebase_token'));

    // GROUP 22: Sensitive shell history & dotfiles
    queries.push(qOr('filename:.bash_history', 'filename:.zsh_history', 'filename:.sh_history', 'filename:.mysql_history'));
    queries.push(qOr('filename:.npmrc', 'filename:.pypirc', 'filename:.netrc', 'filename:.gem/credentials'));

    // GROUP 23: Password & credential text files
    queries.push(qOr('filename:password.txt', 'filename:passwords.txt', 'filename:credentials.txt', 'filename:creds.txt', 'filename:secret.txt'));

    // GROUP 24: FTP & legacy protocols
    queries.push(qOr('ftp_password', 'sftp_password'));
    queries.push(qOr('filename:.ftpconfig', 'filename:ftp.json'));

    // GROUP 25: Secret managers & vaults
    queries.push(qOr('vault_token', 'VAULT_ADDR', 'hvs.', 'doppler_token'));
    queries.push(q('filename:.vault-token'));

    // GROUP 26: Artifactory & package registry auth
    queries.push(qOr('artifactory', 'jfrog', 'AKCp', 'pip.conf'));
    queries.push(q('filename:.pypirc'));

    // GROUP 27: Identity providers — Okta, Auth0, Keycloak
    queries.push(qOr('okta_token', 'auth0_secret', 'keycloak'));
    queries.push(qOr('OKTA_API_TOKEN', 'AUTH0_CLIENT_SECRET'));

    // GROUP 28: Extension-based sensitive searches
    queries.push(q('extension:pem "PRIVATE KEY"'));
    queries.push(qOr('extension:env password', 'extension:env secret', 'extension:env token', 'extension:env key'));

    // GROUP 29: Token prefix hunting
    queries.push(qOr('"AKIA"', '"eyJhbGciOiJIUzI1NiIs"', '"sk_live_"', '"rk_live_"'));

    // GROUP 30: NoSQL & search engine credentials
    queries.push(qOr('MONGO_URI', 'MONGO_PASSWORD', 'REDIS_URL'));
    queries.push(qOr('REDIS_PASSWORD', 'ELASTICSEARCH_URL', 'ELASTIC_PASSWORD'));
    queries.push(qOr('filename:elasticsearch.yml password', 'filename:mongo.conf password', 'filename:redis.conf password', 'filename:mongodb.yml password', 'filename:.pgpass password'));

    // GROUP 31: SSH private key files by name
    queries.push(qOr('filename:id_rsa', 'filename:id_dsa', 'filename:id_ed25519', 'filename:id_ecdsa'));

    // GROUP 32: AWS credentials files
    queries.push(qOr('filename:.aws/credentials aws_access_key_id', 'filename:credentials aws_access_key_id'));

    // GROUP 33: High-value config files & extensions
    queries.push(qOr('filename:config.json password', 'filename:database.yml password', 'filename:appsettings.json password', 'filename:settings.json password'));
    queries.push(qOr('filename:config.json secret', 'filename:database.yml secret', 'filename:appsettings.json secret', 'filename:settings.json secret'));
    queries.push(qOr('extension:json api_key', 'extension:yml api_key', 'extension:ini api_key', 'extension:yaml api_key'));
    queries.push(qOr('extension:json password', 'extension:yml password', 'extension:ini password', 'extension:yaml password'));
    queries.push(qOr('extension:conf password', 'extension:cfg password', 'extension:xml password'));
    queries.push(qOr('extension:sql password', 'extension:sql dump'));

    // GROUP 34: Kubernetes expanded
    queries.push(qOr('filename:.kube/config', 'filename:kubeconfig', 'filename:secrets.yaml'));
    queries.push(qOr('kubectl', 'kubernetes'));

    // GROUP 35: OAuth & client secrets
    queries.push(qOr('oauth_secret', 'client_credentials'));
    queries.push(q('filename:oauth.json'));
    queries.push(q('client_id client_secret'));

    // GROUP 36: Jenkins & CI expanded
    queries.push(qOr('JENKINS_API_TOKEN', 'JENKINS_PASSWORD', 'buildkite'));
    queries.push(q('filename:jenkins.yml'));

    // GROUP 37: Monitoring expanded
    queries.push(qOr('sentry_dsn', 'SENTRY_AUTH_TOKEN', 'dynatrace'));
    queries.push(q('filename:grafana.ini'));

    // GROUP 38: Additional high-value credential keywords
    queries.push(qOr('GOOGLE_APPLICATION_CREDENTIALS', 'DOCKER_AUTH_CONFIG'));
    queries.push(qOr('PAYPAL_LIVE_API_PASSWORD', 'PAYPAL_LIVE_API_USERNAME'));

    // ===================================================================
    // GROUPS 39–59: Additional dork coverage
    // ===================================================================

    // GROUP 39: Firebase composite auth config (leaked client configs in frontend code)
    queries.push(qOr('firebase apiKey', 'firebase authDomain', 'firebase databaseURL'));

    // GROUP 40: Cloudinary credentials
    queries.push(qOr('cloudinary', 'cloud_name', 'CLOUDINARY_URL'));

    // GROUP 41: Pulumi extended token format (pulumip- prefix)
    queries.push(q('pulumip-'));

    // GROUP 42: Neo4j connection strings
    queries.push(qOr('neo4j', 'neo4j+s://', 'NEO4J_URI'));

    // GROUP 43: SQL Server / OLEDB connection strings
    queries.push(qOr('sqlserver', 'sqloledb', '"Data Source=" password'));

    // GROUP 44: DBeaver & Robomongo/Robo3T config files
    queries.push(qOr('filename:dbeaver-data-sources.xml', 'filename:robomongo.json', 'filename:robo3t.json'));

    // GROUP 45: Certificate extension:cer (was missing from GROUP 19)
    queries.push(q('extension:cer'));

    // GROUP 46: 1Password token pattern
    queries.push(q('"ops_eyJ"'));

    // GROUP 47: ProFTPD, DHCP, and server config files
    queries.push(qOr('filename:proftpdpasswd', 'filename:dhcpd.conf', 'filename:server.cfg'));

    // GROUP 48: IDE workspace files (leaked secrets in IDE settings)
    queries.push(qOr('path:.vscode filename:settings.json', 'path:.idea filename:workspace.xml', 'filename:vim_settings.xml'));

    // GROUP 49: Proxifier, ngrok, Vagrant, RDP, ICA configs
    queries.push(qOr('filename:ngrok.yml', 'filename:Vagrantfile password', 'extension:rdp', 'extension:ica'));

    // GROUP 50: Nmap scan output files
    queries.push(qOr('extension:nmap', 'extension:gnmap'));

    // GROUP 51: Dangerous PHP functions (webshell / RCE indicators)
    queries.push(qOr('shell_exec', '"system("', '"eval("', '"passthru("'));

    // GROUP 52: Base64-encoded secret prefixes (obfuscation evasion)
    // QUtJQ = AKIA (AWS), c2stb = sk-li (Stripe/OpenAI), eG94 = xox (Slack)
    queries.push(qOr('"QUtJQ"', '"c2stb"', '"eG94"'));

    // GROUP 53: Atlassian / Jira / Trello / Confluence recon
    queries.push(qOr('atlassian.net', 'jira', 'trello.com', 'confluence'));

    // GROUP 54: Admin panels / install scripts / setup files
    queries.push(qOr('wp-admin', '"admin/login"', 'filename:install.php', 'filename:setup.sh'));

    // GROUP 55: Internal/staging/swagger/preprod discovery
    queries.push(qOr('swagger', '"internal-docs"', 'preprod'));

    // GROUP 56: Mailchimp keyword queries
    queries.push(qOr('mailchimp', 'mailchimp_api_key'));

    // GROUP 57: MessageBird / OneSignal / Algolia
    queries.push(qOr('messagebird', 'onesignal', 'algolia_admin_key'));

    // GROUP 58: Zendesk / Freshdesk tokens
    queries.push(qOr('zendesk_token', 'freshdesk_key', 'freshdesk_api_key'));

    // GROUP 59: Rollbar / Sumologic / Codecov tokens
    queries.push(qOr('rollbar_access_token', 'sumologic', 'codecov_token'));

    // ===================================================================
    // GROUPS 60–64: Additional dork coverage
    // ===================================================================

    // GROUP 60: Additional Shell and System Files
    queries.push(qOr('filename:.bash_profile password', 'filename:.bash_profile secret', 'filename:.bashrc password', 'filename:.bashrc secret'));

    // GROUP 61: FTP/SFTP and Workspace configs
    queries.push(qOr('filename:sftp-config.json', 'filename:.remote-sync.json', 'filename:sftp.json', 'filename:filezilla.xml'));
    queries.push(qOr('filename:recentservers.xml', 'filename:WebServers.xml', 'filename:.ftpconfig', 'filename:ftp.json'));

    // GROUP 62: Auth Recovery and Backup Codes
    queries.push(qOr('filename:github-recovery-codes.txt', 'filename:gitlab-recovery-codes.txt', 'filename:discord_backup_codes.txt'));

    // GROUP 63: CMS and Framework Secrets
    queries.push(qOr('filename:secrets.yml', 'filename:master.key', 'filename:prod.secret.exs', 'filename:prod.exs', 'filename:wp-config.php'));

    // GROUP 64: App/Browser Credential Stores & System configs
    queries.push(qOr('filename:logins.json', 'filename:shadow', 'filename:passwd path:etc', 'filename:sshd_config'));

    // ===================================================================
    // GROUPS 65–83: betterleaks.toml 100% comprehensive coverage
    // ===================================================================

    // GROUP 65: AI/ML Service Keys (Extended — betterleaks HIGH priority)
    queries.push(qOr('gsk_', 'GROQ_API_KEY', 'groq'));
    queries.push(qOr('xai-', 'XAI_API_KEY'));
    queries.push(qOr('nvapi-', 'NVIDIA_API_KEY'));
    queries.push(qOr('sk-or-v1-', 'OPENROUTER_API_KEY', 'openrouter'));
    queries.push(qOr('MISTRAL_API_KEY', 'mistral api'));
    queries.push(qOr('DEEPSEEK_API_KEY', 'deepseek api'));
    queries.push(qOr('CEREBRAS_API_KEY', 'csk-'));
    queries.push(qOr('STABILITY_API_KEY', 'stability ai'));

    // GROUP 66: Cloud Service Keys (Extended — betterleaks HIGH priority)
    queries.push(qOr('ABSK', 'bedrock-api-key', 'amazon bedrock'));
    queries.push(qOr('HRKU-', 'heroku api'));

    // GROUP 67: SaaS Communication & Analytics (betterleaks MEDIUM priority)
    queries.push(qOr('ATATT3', 'atlassian api_token'));
    queries.push(qOr('mapbox', 'pk.eyJ', 'MAPBOX_ACCESS_TOKEN'));
    queries.push(qOr('outlook.office.com/webhook', 'teams webhook'));
    queries.push(qOr('FLWSECK_TEST', 'FLWPUBK_TEST', 'flutterwave'));

    // GROUP 68: Developer Tools & Analytics (betterleaks MEDIUM priority)
    queries.push(qOr('posthog', 'phx_', 'phc_', 'POSTHOG_API_KEY'));
    queries.push(qOr('wandb', 'WANDB_API_KEY', 'weights biases'));
    queries.push(qOr('sgp_', 'sourcegraph'));
    queries.push(qOr('elevenlabs', 'ELEVENLABS_API_KEY'));

    // GROUP 69: Finance & AI Platforms (betterleaks MEDIUM priority)
    queries.push(qOr('plaid', 'PLAID_SECRET', 'PLAID_CLIENT_ID'));
    queries.push(qOr('cohere', 'CO_API_KEY'));

    // GROUP 70: Vercel Extended Tokens (betterleaks distinctive prefixes)
    queries.push(qOr('vck_', 'vca_', 'vcr_', 'vci_', 'vcp_'));

    // GROUP 71: Slack Extended Tokens (betterleaks config/legacy)
    queries.push(qOr('xoxe.xox', 'xoxe-', 'xox[ar]-'));

    // GROUP 72: GitLab Extended Tokens (betterleaks CI/deploy/scim)
    queries.push(qOr('glcbt-', 'gldt-', 'glffct-'));
    queries.push(qOr('glft-', 'gloas-', 'glsoat-'));

    // GROUP 73: DevOps & CI/CD Tools
    queries.push(qOr('CLOJARS_', 'clojars'));
    queries.push(qOr('duffel_test', 'duffel_live'));
    queries.push(qOr('EZAK', 'EZTK', 'easypost'));
    queries.push(qOr('fio-u-', 'frameio'));
    queries.push(qOr('harness', 'pat.', 'sat.'));

    // GROUP 74: Infrastructure & Cloud
    queries.push(qOr('ico-', 'infracost'));
    queries.push(qOr('sha256~', 'openshift'));
    queries.push(qOr('pnu_', 'prefect'));
    queries.push(qOr('tk-us-', 'scalingo'));

    // GROUP 75: Shipping & Fintech
    queries.push(qOr('shippo_live', 'shippo_test'));
    queries.push(qOr('sm_aat_', 'sm_pat_', 'sm_sat_', 'settlemint'));

    // GROUP 76: Security Scanning & Dev
    queries.push(qOr('sntryu_', 'sentry user'));
    queries.push(qOr('snyk_token', 'SNYK_TOKEN'));

    // GROUP 77: SaaS, Comms, and Social Media (Category 2 keywords)
    queries.push(qOr('asana', 'beamer', 'contentful', 'intercom', 'mattermost'));
    queries.push(qOr('zendesk', 'facebook', 'eaam', 'eaac', 'flickr'));
    queries.push(qOr('linkedin', 'webhook.office.com', 'sendbird', 'sendinblue'));
    queries.push(qOr('telegram', 'twitch', 'twitter'));

    // GROUP 78: Developer Tools & API Gateways (Category 2 keywords)
    queries.push(qOr('authress', 'scauth_', 'cursor', 'gitea', 'gitter'));
    queries.push(qOr('greptile', 'launchdarkly', 'linear', 'lin_api_'));
    queries.push(qOr('readme', 'replicate', 'sonar', 'typeform', 'yandex'));

    // GROUP 79: Cloud, Data & Infrastructure (Category 2 keywords)
    queries.push(qOr('assemblyai', 'clickhouse', 'confluent', 'databricks', 'deepgram'));
    queries.push(qOr('digitalocean', 'doo_v1_', 'dop_v1_', 'dor_v1_'));
    queries.push(qOr('flyio', 'fo1_', 'fm1', 'fm2_'));
    queries.push(qOr('hashicorp', 'atlasv1', 'planetscale', 'pscale'));
    queries.push(qOr('rapidapi', 'rubygems', 'sidekiq'));

    // GROUP 80: Finance, E-commerce, Logistics & CI/CD (Category 2 keywords)
    queries.push(qOr('coinbase', 'bittrex', 'kraken', 'kucoin'));
    queries.push(qOr('finicity', 'finnhub', 'freshbooks', 'shopify'));
    queries.push(qOr('droneci', 'endorlabs', 'snyk'));

    // GROUP 81: Misc Services (Category 2 keywords)
    queries.push(qOr('cisco meraki', 'dropbox', 'etsy', 'hubspot', 'looker'));
    queries.push(qOr('maxmind', 'notion', 'ntn_', 'nytimes', 'ollama'));
    queries.push(qOr('privateai', 'squarespace'));
    
    // GROUP 82: Misc Utilities
    queries.push(qOr('curl', 'pkcs12', 'nuget'));
    
    // GROUP 83: Remaining Services
    queries.push(qOr('adafruit', 'adobe', 'p8e-', 'airtable', 'alibaba'));
    queries.push(qOr('ltai', 'fastly', 'freemius', 'intra42', 's-s4t2'));
    queries.push(qOr('togetherai', 'tgp_v1_'));

    return queries;
  }

  /**
   * Scan commits with targeted queries
   */
  private async scanCommits(
    scanId: string,
    domain: string,
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const commitQueries = [
        // --- Original queries ---
        domain,
        `${domain} password`,
        `${domain} secret`,
        `${domain} key`,
        `${domain} token`,
        `remove ${domain}`,
        `fix ${domain} credential`,
        `${domain} leak`,
        `${domain} exposed`,
        `${domain} api key`,
        `${domain} security fix`,
        `revert ${domain} credential`,
        // --- Credential rotation signals ---
        `${domain} rotate key`,
        `${domain} rotate token`,
        `${domain} rotate secret`,
        `${domain} regenerate`,
        `${domain} revoke`,
        // --- Accident acknowledgment patterns ---
        `${domain} accidentally`,
        `${domain} should not`,
        `${domain} oops`,
        // --- .env / config removal signals ---
        `${domain} remove .env`,
        `${domain} remove config`,
        `${domain} remove credentials`,
        `${domain} gitignore`,
        // --- Service-specific commit messages ---
        `${domain} AWS`,
        `${domain} stripe`,
        `${domain} firebase`,
        // --- Remediation signals ---
        `${domain} hotfix credential`,
        `${domain} patch secret`,
        `${domain} update password`,
      ];

      const allPatterns = [...SECRET_PATTERNS, ...getDomainPatterns(domain)];
      let queryIndex = 0;

      for (const query of commitQueries) {
        if (signal.aborted) break;
        queryIndex++;
        await onProgress(queryIndex, commitQueries.length, `Commits: "${query}"`);

        try {
          const pagesToFetch = 10;
          const perPage = 100;
          const allPageResults: any[] = [];

          for (let page = 1; page <= pagesToFetch; page++) {
            if (signal.aborted) break;
            try {
              const pageResults = await this.githubService.searchCommits(query, { perPage, page });
              allPageResults.push(...pageResults);
              if (pageResults.length < perPage) break;
            } catch (pageError: any) {
              if (pageError.status === 422) {
                logger.warn(`Commit Query ${queryIndex}/${commitQueries.length} skipped (GitHub API 422 parsing error)`);
                break;
              }
              if (page === 1) throw pageError;
              break;
            }
          }
          
          const results = allPageResults;
          logger.info(`Commit query ${queryIndex}/${commitQueries.length} "${query}" → ${results.length} results`);

          for (const result of results) {
            if (signal.aborted) break;

            // Domain substring validation: check message AND author/committer emails
            const authorEmailMatch = result.authorEmail && domainValidationRegex.test(result.authorEmail);
            const committerEmailMatch = result.committerEmail && domainValidationRegex.test(result.committerEmail);
            if (!domainValidationRegex.test(result.message) && !authorEmailMatch && !committerEmailMatch) {
              logger.debug(`Skipping commit ${result.commitSha} in ${result.repository} (domain substring mismatch)`);
              continue;
            }

            const secrets = this.extractSecrets(result.message, allPatterns);

            // Also extract emails from commit author/committer metadata (including subdomains)
            const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const emailRegex = new RegExp(`[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\\.)*${escapedDomain}(?![a-zA-Z0-9.-])`, 'i');
            if (result.authorEmail && emailRegex.test(result.authorEmail)) {
              secrets.push({ type: 'EMAIL', content: result.authorEmail, matchIndex: 0 });
            }
            if (result.committerEmail && emailRegex.test(result.committerEmail) && result.committerEmail !== result.authorEmail) {
              secrets.push({ type: 'EMAIL', content: result.committerEmail, matchIndex: 0 });
            }

            const validSecrets = [];
            for (const secret of secrets) {
              // Use 'commit-message' + commitSha as the unique path component
              // so cross-scan dedup works correctly per commit.
              const contentHash = this.hashContent(secret.content + result.repository + `commit-message-${result.commitSha}`);
              if (seenHashes.has(contentHash)) continue;
              seenHashes.add(contentHash);

              const context = result.message;
              if (isFalsePositive(secret.content, context)) continue;

              const entropy = calculateEntropy(secret.content);
              const score = calculateCriticalityScore({
                type: secret.type, content: secret.content, context,
                repository: result.repository, commitDate: result.commitDate, entropy
              });
              const criticality = scoreToCriticality(score);

              validSecrets.push({
                type: secret.type,
                content: secret.content,
                contentPreview: createPreview(secret.content),
                context,
                score,
                criticality
              });
            }

            if (validSecrets.length === 0) continue;

            const { score: fileScore, primaryType, criticality: fileCriticality } = calculateFileCriticalityScore(validSecrets);

            const finding = await prisma.finding.create({
              data: {
                scanId,
                repository: result.repository,
                repositoryUrl: result.repositoryUrl,
                filePath: result.commitSha,
                fileUrl: result.commitUrl,
                commitSha: result.commitSha,
                commitUrl: result.commitUrl,
                commitDate: result.commitDate,
                score: fileScore,
                primaryType,
                criticality: fileCriticality,
                secrets: {
                  create: validSecrets.map(s => ({
                    type: s.type,
                    criticality: s.criticality,
                    content: s.content,
                    contentPreview: s.contentPreview,
                    context: s.context
                  }))
                }
              },
              include: { secrets: true }
            });
            findings.push(finding);
          }
        } catch (error: any) {
          if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
          logger.error(`Error processing commit query "${query}":`, error);
        }
      }
    } catch (error: any) {
      if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
      logger.error('Error in scanCommits:', error);
    }

    return findings;
  }

  /**
   * Scan issues with targeted queries
   */
  private async scanIssues(
    scanId: string,
    domain: string,
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const issueQueries = [
        // --- Original queries ---
        domain,
        `${domain} credentials`,
        `${domain} api key`,
        `${domain} password`,
        `${domain} token`,
        `${domain} secret leaked`,
        `${domain} vulnerability`,
        `${domain} exposed`,
        `${domain} config`,
        // --- Help-seeking patterns (users paste creds asking for help) ---
        `${domain} not working`,
        `${domain} error 401`,
        `${domain} error 403`,
        `${domain} connection refused`,
        // --- Bug report credential leaks ---
        `${domain} stack trace`,
        `${domain} log output`,
        // --- Configuration discussion ---
        `${domain} environment variable`,
        `${domain} .env`,
        `${domain} setup guide`,
        // --- Security disclosure ---
        `${domain} security issue`,
        `${domain} data breach`,
        `${domain} responsible disclosure`,
        // --- Access and authentication ---
        `${domain} authentication`,
        `${domain} login failed`,
        `${domain} access denied`,
      ];

      const allPatterns = [...SECRET_PATTERNS, ...getDomainPatterns(domain)];
      let queryIndex = 0;

      for (const query of issueQueries) {
        if (signal.aborted) break;
        queryIndex++;
        await onProgress(queryIndex, issueQueries.length, `Issues: "${query}"`);

        try {
          const pagesToFetch = 10;
          const perPage = 100;
          const allPageResults: any[] = [];

          for (let page = 1; page <= pagesToFetch; page++) {
            if (signal.aborted) break;
            try {
              const pageResults = await this.githubService.searchIssues(query, { perPage, page });
              allPageResults.push(...pageResults);
              if (pageResults.length < perPage) break;
            } catch (pageError: any) {
              if (pageError.status === 422) {
                logger.warn(`Issue Query ${queryIndex}/${issueQueries.length} skipped (GitHub API 422 parsing error)`);
                break;
              }
              if (page === 1) throw pageError;
              break;
            }
          }

          const results = allPageResults;
          logger.info(`Issue query ${queryIndex}/${issueQueries.length} "${query}" → ${results.length} results`);

          for (const result of results) {
            if (signal.aborted) break;
            const content = `${result.title}\n\n${result.body}`;

            // Domain substring validation: skip issues where the domain only appears
            // as part of a larger word (e.g. "sub.example.com" when scanning "example.com")
            if (!domainValidationRegex.test(content)) {
              logger.debug(`Skipping issue ${result.url} (domain substring mismatch)`);
              continue;
            }

            const secrets = this.extractSecrets(content, allPatterns);

            // Also detect credential pairs (email + password in same issue)
            const credentialPairs = this.detectCredentialPairs(content, domain);
            const allSecrets = [...secrets, ...credentialPairs];

            const validSecrets = [];
            for (const secret of allSecrets) {
              // Use 'issue' + issueNumber as the unique path component
              // so cross-scan dedup works correctly per issue.
              const contentHash = this.hashContent(secret.content + result.repository + `issue-${result.issueNumber}`);
              if (seenHashes.has(contentHash)) continue;
              seenHashes.add(contentHash);

              const context = extractContext(content, secret.matchIndex);

              // Don't false-positive-filter credential pairs or passwords with explicit labels
              if (secret.type !== 'CREDENTIAL_PAIR' && isFalsePositive(secret.content, context)) continue;

              const entropy = calculateEntropy(secret.content);

              let score: number;
              let criticality: string;

              if (secret.type === 'CREDENTIAL_PAIR') {
                // Force HIGH for credential pairs — email:password is always HIGH severity
                score = 80;
                criticality = 'HIGH';
              } else if (secret.type === 'EMAIL') {
                // If there's a credential pair in the same content, bump email to MEDIUM
                const hasPairNearby = credentialPairs.length > 0;
                if (hasPairNearby) {
                  score = 55;
                  criticality = 'MEDIUM';
                } else {
                  score = calculateCriticalityScore({
                    type: secret.type, content: secret.content, context,
                    repository: result.repository, entropy
                  });
                  criticality = scoreToCriticality(score);
                }
              } else {
                score = calculateCriticalityScore({
                  type: secret.type, content: secret.content, context,
                  repository: result.repository, entropy
                });
                criticality = scoreToCriticality(score);
              }

              validSecrets.push({
                type: secret.type,
                content: secret.content,
                contentPreview: createPreview(secret.content),
                context,
                score,
                criticality
              });
            }

            if (validSecrets.length === 0) continue;

            const { score: fileScore, primaryType, criticality: fileCriticality } = calculateFileCriticalityScore(validSecrets);

            const finding = await prisma.finding.create({
              data: {
                scanId,
                repository: result.repository,
                repositoryUrl: result.url,
                filePath: `issue-${result.issueNumber}`,
                issueNumber: result.issueNumber,
                score: fileScore,
                primaryType,
                criticality: fileCriticality,
                secrets: {
                  create: validSecrets.map(s => ({
                    type: s.type,
                    criticality: s.criticality,
                    content: s.content,
                    contentPreview: s.contentPreview,
                    context: s.context
                  }))
                }
              },
              include: { secrets: true }
            });
            findings.push(finding);
          }
        } catch (error: any) {
          if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
          logger.error(`Error processing issue query "${query}":`, error);
        }
      }
    } catch (error: any) {
      if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
      logger.error('Error in scanIssues:', error);
    }

    return findings;
  }

  /**
   * Extract secrets from content using patterns
   */
  private extractSecrets(content: string, patterns: any[]): ExtractedSecret[] {
    const secrets: ExtractedSecret[] = [];

    for (const pattern of patterns) {
      if (pattern.pattern.global) {
        pattern.pattern.lastIndex = 0;
      }

      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const matchedContent = match[0];
        const matchIndex = match.index || 0;

        if (pattern.entropyThreshold) {
          const entropy = calculateEntropy(matchedContent);
          if (entropy < pattern.entropyThreshold) continue;
        }

        secrets.push({ type: pattern.type, content: matchedContent, matchIndex });
      }
    }

    return secrets;
  }

  /**
   * Detect credential pairs (email + password in same content)
   * This is a critical CTI finding: exposed credentials in issues/code
   * Returns additional CREDENTIAL_PAIR findings when email + password co-occur
   */
  private detectCredentialPairs(content: string, domain: string): ExtractedSecret[] {
    const pairs: ExtractedSecret[] = [];
    const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // Find all domain emails in content (including subdomains)
    const emailRegex = new RegExp(`[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\\.)*${escapedDomain}(?![a-zA-Z0-9.-])`, 'gi');
    const emails: { email: string; index: number }[] = [];
    let emailMatch;
    while ((emailMatch = emailRegex.exec(content)) !== null) {
      emails.push({ email: emailMatch[0], index: emailMatch.index });
    }

    if (emails.length === 0) return pairs;

    // Find all password-like values in content (very broad — catches "Password: test", "pwd=abc", etc.)
    const pwdRegex = /(?:password|passwd|pwd|pass)\s*[:=]\s*(\S+)/gi;
    const passwords: { full: string; value: string; index: number }[] = [];
    let pwdMatch;
    while ((pwdMatch = pwdRegex.exec(content)) !== null) {
      passwords.push({ full: pwdMatch[0], value: pwdMatch[1], index: pwdMatch.index });
    }

    if (passwords.length === 0) return pairs;

    // Also look for "User Name:" / "Username:" / "Login:" patterns near emails
    const userPassBlockRegex = /(?:user\s*(?:name)?|login|email|account)\s*[:=]\s*(\S+@\S+)[\s\S]{0,200}?(?:password|passwd|pwd|pass)\s*[:=]\s*(\S+)/gi;
    let blockMatch;
    while ((blockMatch = userPassBlockRegex.exec(content)) !== null) {
      const email = blockMatch[1];
      const password = blockMatch[2];
      // Only care about domain-matching emails (including subdomains)
      const lowerEmail = email.toLowerCase();
      const lowerDomain = domain.toLowerCase();
      if (lowerEmail.endsWith(`@${lowerDomain}`) || lowerEmail.endsWith(`.${lowerDomain}`)) {
        const pairContent = `${email}:${password}`;
        pairs.push({
          type: 'CREDENTIAL_PAIR',
          content: pairContent,
          matchIndex: blockMatch.index
        });
      }
    }

    // Fallback: if we found domain emails AND passwords within 500 chars of each other
    if (pairs.length === 0) {
      for (const email of emails) {
        for (const pwd of passwords) {
          const distance = Math.abs(email.index - pwd.index);
          if (distance < 500) {
            const pairContent = `${email.email}:${pwd.value}`;
            pairs.push({
              type: 'CREDENTIAL_PAIR',
              content: pairContent,
              matchIndex: Math.min(email.index, pwd.index)
            });
            break; // One pair per email
          }
        }
      }
    }

    return pairs;
  }

  /**
   * Hash content for deduplication
   */
  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Cancel a running scan
   */
  async cancelScan(scanId: string): Promise<boolean> {
    const controller = activeScans.get(scanId);

    if (controller) {
      controller.abort();
      logger.info(`Scan ${scanId} abort signal sent`);
      return true;
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'CANCELLED', completedAt: new Date(), errorMessage: 'Scan cancelled by user' }
    });

    logger.info(`Scan ${scanId} cancelled (was not actively running)`);
    return true;
  }
}

export default ScannerService;
