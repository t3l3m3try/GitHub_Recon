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
import {
  ResolvedQuery,
  getEnabledQueryIds,
  resolveQueriesForTarget
} from './queryPreferences.service';
import { logger } from '../utils/logger';
import crypto from 'crypto';

/**
 * Scanner Service
 * Orchestrates the scanning process for a domain
 * Supports abort/cancel and real-time progress tracking with percentage
 *
 * Which queries run is entirely driven by the user's selection in the Queries
 * section — see utils/queryCatalog.ts and services/queryPreferences.service.ts.
 * A target whose queries are all disabled is skipped outright.
 */

interface ExtractedSecret {
  type: string;
  content: string;
  matchIndex: number;
}

// Global registry of active scans for cancellation
const activeScans = new Map<string, AbortController>();

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
  async executeScan(scanId: string, domain: string, options: { userId: string }): Promise<void> {
    const { userId } = options;

    // Resolve the user's enabled queries up front — this drives both which
    // phases run and the denominator of the progress percentage.
    const enabledIds = await getEnabledQueryIds(userId);
    const codeQueries = resolveQueriesForTarget('code', enabledIds, domain);
    const commitQueries = resolveQueriesForTarget('commits', enabledIds, domain);
    const issueQueries = resolveQueriesForTarget('issues', enabledIds, domain);

    const includeCode = codeQueries.length > 0;
    const includeCommits = commitQueries.length > 0;
    const includeIssues = issueQueries.length > 0;
    const totalSteps = codeQueries.length + commitQueries.length + issueQueries.length;

    // Create abort controller for this scan
    const abortController = new AbortController();
    activeScans.set(scanId, abortController);
    const signal = abortController.signal;

    // Track global step counter for percentage
    let completedSteps = 0;
    let lastProgressUpdate = 0;

    const updateProgress = async (phase: string, stepInPhase: number, totalInPhase: number, message: string, findingsCount: number) => {
      const percent = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 100;

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

      logger.info(
        `Starting scan ${scanId} for domain: ${domain} — ${totalSteps} enabled queries ` +
        `(code: ${codeQueries.length}, commits: ${commitQueries.length}, issues: ${issueQueries.length})`
      );

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

      // 1. Scan code repositories
      if (includeCode) {
        checkAbort();
        logger.info(`Phase 1/3: Scanning code repositories (${codeQueries.length} queries)...`);
        const codeFindings = await this.scanCode(scanId, domain, codeQueries, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = step;
          await updateProgress('code', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...codeFindings);
        completedSteps = codeQueries.length;
      }

      // 2. Scan commits
      if (includeCommits) {
        checkAbort();
        logger.info(`Phase 2/3: Scanning commits (${commitQueries.length} queries)...`);
        const commitFindings = await this.scanCommits(scanId, domain, commitQueries, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = codeQueries.length + step;
          await updateProgress('commits', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...commitFindings);
        completedSteps = codeQueries.length + commitQueries.length;
      }

      // 3. Scan issues
      if (includeIssues) {
        checkAbort();
        logger.info(`Phase 3/3: Scanning issues (${issueQueries.length} queries)...`);
        const issueFindings = await this.scanIssues(scanId, domain, issueQueries, signal, seenContentHashes, domainValidationRegex, async (step, total, msg) => {
          completedSteps = codeQueries.length + commitQueries.length + step;
          await updateProgress('issues', step, total, msg, allRawFindings.length);
        });
        allRawFindings.push(...issueFindings);
        completedSteps = totalSteps;
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
    queries: ResolvedQuery[],
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const domainPatterns = getDomainPatterns(domain);
      const allPatterns = [...SECRET_PATTERNS, ...domainPatterns];

      let queryIndex = 0;
      let skippedQueries = 0;
      // Identify email-specific queries for multi-page logging
      const emailQueryPrefix = `"@${domain}"`;
      for (const { label, query } of queries) {
        if (signal.aborted) break;
        queryIndex++;
        await onProgress(queryIndex, queries.length, `Code: ${label}`);

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
          logger.info(`Query ${queryIndex}/${queries.length} "${label}"${isEmailQuery ? ' [EMAIL-MULTI-PAGE]' : ''} → ${results.length} results`);

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
          logger.error(`Error processing query "${label}":`, error);
        }
      }
    } catch (error: any) {
      if (error.message === 'SCAN_CANCELLED' || signal.aborted) throw error;
      logger.error('Error in scanCode:', error);
    }

    return findings;
  }

  /**
   * Scan commits with targeted queries
   */
  private async scanCommits(
    scanId: string,
    domain: string,
    commitQueries: ResolvedQuery[],
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const allPatterns = [...SECRET_PATTERNS, ...getDomainPatterns(domain)];
      let queryIndex = 0;

      for (const { label, query } of commitQueries) {
        if (signal.aborted) break;
        queryIndex++;
        await onProgress(queryIndex, commitQueries.length, `Commits: ${label}`);

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
          logger.error(`Error processing commit query "${label}":`, error);
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
    issueQueries: ResolvedQuery[],
    signal: AbortSignal,
    seenHashes: Set<string>,
    domainValidationRegex: RegExp,
    onProgress: (step: number, total: number, message: string) => Promise<void>
  ): Promise<any[]> {
    const findings: any[] = [];

    try {
      const allPatterns = [...SECRET_PATTERNS, ...getDomainPatterns(domain)];
      let queryIndex = 0;

      for (const { label, query } of issueQueries) {
        if (signal.aborted) break;
        queryIndex++;
        await onProgress(queryIndex, issueQueries.length, `Issues: ${label}`);

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
          logger.info(`Issue query ${queryIndex}/${issueQueries.length} "${label}" (${query}) → ${results.length} results`);

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
          logger.error(`Error processing issue query "${label}":`, error);
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
