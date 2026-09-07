import { Octokit } from '@octokit/rest';
import Bottleneck from 'bottleneck';
import https from 'https';
import { logger } from '../utils/logger';
import { isValidCommitterEmail, cleanCommitterEmail } from '../utils/committerValidator';

export interface ExtractedCommitter {
  email: string;
  name?: string;
  commitSha?: string;
  commitDate?: Date;
}

export interface FileCommitDetails {
  commitDate?: Date;
  commitSha?: string;
  commitUrl?: string;
  primaryEmail?: string;
  committers: ExtractedCommitter[];
}

/**
 * GitHub Service
 * Handles all interactions with GitHub API with rate limiting
 */

export interface SearchResult {
  repository: string;
  repositoryUrl: string;
  filePath: string;
  content: string;
  sha: string;
  htmlUrl: string;
  commitSha?: string;
  commitUrl?: string;
  commitDate?: Date;
  committerEmail?: string;
  committers?: ExtractedCommitter[];
  branch?: string;
}


export interface IssueResult {
  repository: string;
  issueNumber: number;
  title: string;
  body: string;
  url: string;
  createdAt: Date;
  state: string;
}

export interface CommitResult {
  repository: string;
  repositoryUrl: string;
  commitSha: string;
  commitUrl: string;
  commitDate: Date;
  message: string;
  author: string;
  authorEmail?: string;
  committerEmail?: string;
  files: {
    filename: string;
    patch?: string;
    status: string;
  }[];
}

/**
 * Rate limiters are module-level singletons, not per-instance.
 *
 * Every scan constructs its own GitHubService, but all of them authenticate
 * with the same GITHUB_TOKEN and so draw against the same GitHub-side quota.
 * A per-instance Bottleneck would let N concurrent scans each believe they
 * have the full 30 req/min, sending up to N*30 to GitHub and drawing 403s —
 * these two limiters are shared by every GitHubService in the process so the
 * real quota is enforced once, in total, regardless of how many domains are
 * scanning at once. Concurrent scans still complete correctly; they just
 * divide the same budget and take proportionally longer.
 */

// Search API rate limiter — GitHub enforces 30 requests/min for code search
const SEARCH_LIMITER = new Bottleneck({
  reservoir: 30,
  reservoirRefreshAmount: 30,
  reservoirRefreshInterval: 60 * 1000,
  maxConcurrent: 3,  // Reduced from 5 to limit peak parallel queries
  minTime: 2000
});

// Core API rate limiter — GitHub allows 5000 requests/hour (~83/min)
// Used for blob fetches which are NOT subject to the search rate limit
const CORE_LIMITER = new Bottleneck({
  reservoir: 80,
  reservoirRefreshAmount: 80,
  reservoirRefreshInterval: 60 * 1000,
  maxConcurrent: 3, // Reduced from 10 to flatten CPU load during heavy blob parsing
  minTime: 500      // Decreased to speed up parallel blob fetching
});

// Process-wide in-memory LRU caches to save GitHub API quota across queries, scans, and server lifetime
const GLOBAL_BLOB_CACHE = new Map<string, string>();
const MAX_BLOB_CACHE_SIZE = 1000;

const GLOBAL_COMMIT_DETAILS_CACHE = new Map<string, FileCommitDetails>();
const MAX_COMMIT_CACHE_SIZE = 2000;

class GitHubService {
  private octokit: Octokit;
  private limiter = SEARCH_LIMITER;
  private coreLimiter = CORE_LIMITER;

  constructor(token: string) {
    this.octokit = new Octokit({
      auth: token,
      userAgent: 'GitHub-CTI-Monitor/1.0',
      request: {
        headers: {
          accept: 'application/vnd.github+json'
        }
      }
    });
  }

  /**
   * Search for code containing domain or secrets
   */
  async searchCode(
    query: string,
    options: {
      perPage?: number;
      page?: number;
      sort?: 'indexed';
      order?: 'desc' | 'asc';
      retries?: number;
    } = {}
  ): Promise<SearchResult[]> {
    try {
      const { perPage = 30, page = 1, sort, order } = options;

      logger.info(`Searching code: ${query} (page ${page})`);

      const response = await this.limiter.schedule(() =>
        this.octokit.rest.search.code({
          q: query,
          per_page: perPage,
          page,
          sort,
          order
        })
      );

      const results = await Promise.all(
        response.data.items.map(async (item) => {
          try {
            // Use blob API with item.sha (blob SHA) — getContent with blob SHA returns 404
            const content = await this.getBlobContent(
              item.repository.owner.login,
              item.repository.name,
              item.sha
            );

            return {
              repository: item.repository.full_name,
              repositoryUrl: item.repository.html_url,
              filePath: item.path,
              content,
              sha: item.sha,
              htmlUrl: item.html_url,
            };
          } catch (error) {
            logger.error(`Error fetching content for ${item.path}:`, error);
            return null;
          }
        })
      );

      return results.filter((r): r is SearchResult => r !== null);
    } catch (error: any) {
      const remainingRetries = options.retries ?? 3;
      if ((error.status === 403 || error.status === 429) && remainingRetries > 0) {
        await this.handleRateLimitError(error);
        // Exponential backoff logic is inside handleRateLimitError or inherited by the natural delay
        // We decrement retries to eventually fail if GitHub perma-blocks us
        return this.searchCode(query, { ...options, retries: remainingRetries - 1 });
      }
      if (error.status === 422) {
        logger.warn(`Code search query parse error (422): ${error.message}`);
      } else {
        logger.error('Code search error:', error);
      }
      throw error;
    }
  }

  /**
   * Search commits
   */
  async searchCommits(
    query: string,
    options: { perPage?: number; page?: number; retries?: number } = {}
  ): Promise<CommitResult[]> {
    try {
      const { perPage = 30, page = 1 } = options;

      logger.info(`Searching commits: ${query} (page ${page})`);

      const response = await this.limiter.schedule(() =>
        this.octokit.rest.search.commits({
          q: query,
          per_page: perPage,
          page,
          sort: 'committer-date',
          order: 'desc'
        })
      );

      return response.data.items.map(item => ({
        repository: item.repository.full_name,
        repositoryUrl: item.repository.html_url,
        commitSha: item.sha,
        commitUrl: item.html_url,
        commitDate: new Date(item.commit.committer?.date ?? item.commit.author?.date ?? Date.now()),
        message: item.commit.message,
        author: item.commit.author.name,
        authorEmail: item.commit.author?.email || undefined,
        committerEmail: item.commit.committer?.email || undefined,
        files: [] // Files would need separate API call
      }));
    } catch (error: any) {
      const remainingRetries = options.retries ?? 3;
      if ((error.status === 403 || error.status === 429) && remainingRetries > 0) {
        await this.handleRateLimitError(error);
        return this.searchCommits(query, { ...options, retries: remainingRetries - 1 });
      }
      logger.error('Commit search error:', error);
      throw error;
    }
  }

  /**
   * Search issues
   */
  async searchIssues(
    query: string,
    options: { perPage?: number; page?: number; retries?: number } = {}
  ): Promise<IssueResult[]> {
    try {
      const { perPage = 30, page = 1 } = options;

      logger.info(`Searching issues: ${query} (page ${page})`);

      const response = await this.limiter.schedule(() =>
        this.octokit.rest.search.issuesAndPullRequests({
          q: query,
          per_page: perPage,
          page
        })
      );

      return response.data.items.map(item => ({
        repository: item.repository_url.split('/').slice(-2).join('/'),
        issueNumber: item.number,
        title: item.title,
        body: item.body || '',
        url: item.html_url,
        createdAt: new Date(item.created_at),
        state: item.state
      }));
    } catch (error: any) {
      const remainingRetries = options.retries ?? 3;
      if ((error.status === 403 || error.status === 429) && remainingRetries > 0) {
        await this.handleRateLimitError(error);
        return this.searchIssues(query, { ...options, retries: remainingRetries - 1 });
      }
      logger.error('Issue search error:', error);
      throw error;
    }
  }

  /**
   * Get file content
   */
  /**
   * Fetch file content using the git blob API (correct way when you have a blob SHA).
   * The search API returns item.sha as the blob SHA — passing it to getContent as 'ref'
   * returns 404 because getContent expects a commit SHA, branch, or tag as ref.
   * The blob API directly fetches by blob SHA and always works.
   */
  private async getBlobContent(
    owner: string,
    repo: string,
    blobSha: string
  ): Promise<string> {
    if (GLOBAL_BLOB_CACHE.has(blobSha)) {
      return GLOBAL_BLOB_CACHE.get(blobSha)!;
    }

    try {
      const response = await this.coreLimiter.schedule(() =>
        this.octokit.rest.git.getBlob({
          owner,
          repo,
          file_sha: blobSha
        })
      );

      const content = response.data.encoding === 'base64'
        ? Buffer.from(response.data.content, 'base64').toString('utf-8')
        : response.data.content;

      // LRU cache eviction if size limit reached
      if (GLOBAL_BLOB_CACHE.size >= MAX_BLOB_CACHE_SIZE) {
        const firstKey = GLOBAL_BLOB_CACHE.keys().next().value;
        if (firstKey) GLOBAL_BLOB_CACHE.delete(firstKey);
      }
      GLOBAL_BLOB_CACHE.set(blobSha, content);

      return content;
    } catch (error) {
      logger.error(`Error fetching blob ${blobSha} from ${owner}/${repo}:`, error);
      return '';
    }
  }

  /**
   * Get the last commit date for a specific file path
   * Uses Core API limiter (not search) — safe to call per-finding
   */
  async getFileLastCommitDate(repository: string, filePath: string): Promise<Date | undefined> {
    const details = await this.getFileCommitDetails(repository, filePath, 1);
    return details.commitDate;
  }

  /**
   * Get commit details and all valid committers for a specific file path
   * Uses Core API limiter. Extracts commit SHA, date, and valid committer emails.
   */
  async getFileCommitDetails(
    repository: string,
    filePath: string,
    perPage: number = 5
  ): Promise<FileCommitDetails> {
    const cacheKey = `${repository}:${filePath}:${perPage}`;
    if (GLOBAL_COMMIT_DETAILS_CACHE.has(cacheKey)) {
      return GLOBAL_COMMIT_DETAILS_CACHE.get(cacheKey)!;
    }

    const result: FileCommitDetails = {
      committers: []
    };

    try {
      const [owner, repo] = repository.split('/');
      if (!owner || !repo) return result;

      const response = await this.coreLimiter.schedule(() =>
        this.octokit.rest.repos.listCommits({
          owner,
          repo,
          path: filePath,
          per_page: perPage
        })
      );

      if (response.data && response.data.length > 0) {
        const latestCommit = response.data[0];
        result.commitSha = latestCommit.sha;
        result.commitUrl = latestCommit.html_url;

        const dateStr = latestCommit.commit.committer?.date || latestCommit.commit.author?.date;
        if (dateStr) {
          result.commitDate = new Date(dateStr);
        }

        const seenEmails = new Set<string>();

        for (const item of response.data) {
          const itemSha = item.sha;
          const itemDateStr = item.commit.committer?.date || item.commit.author?.date;
          const itemDate = itemDateStr ? new Date(itemDateStr) : undefined;

          // Check committer
          const rawCommitterEmail = item.commit.committer?.email;
          const committerName = item.commit.committer?.name;
          if (isValidCommitterEmail(rawCommitterEmail)) {
            const cleaned = cleanCommitterEmail(rawCommitterEmail)!;
            if (!seenEmails.has(cleaned)) {
              seenEmails.add(cleaned);
              result.committers.push({
                email: cleaned,
                name: committerName,
                commitSha: itemSha,
                commitDate: itemDate
              });
              if (!result.primaryEmail) {
                result.primaryEmail = cleaned;
              }
            }
          }

          // Check author
          const rawAuthorEmail = item.commit.author?.email;
          const authorName = item.commit.author?.name;
          if (isValidCommitterEmail(rawAuthorEmail)) {
            const cleaned = cleanCommitterEmail(rawAuthorEmail)!;
            if (!seenEmails.has(cleaned)) {
              seenEmails.add(cleaned);
              result.committers.push({
                email: cleaned,
                name: authorName,
                commitSha: itemSha,
                commitDate: itemDate
              });
              if (!result.primaryEmail) {
                result.primaryEmail = cleaned;
              }
            }
          }
        }

        logger.info(
          `File commit details fetched for ${repository}/${filePath}: ${result.committers.length} committer(s), primary: ${result.primaryEmail || 'none'}`
        );
      }

      // Cache the result
      if (GLOBAL_COMMIT_DETAILS_CACHE.size >= MAX_COMMIT_CACHE_SIZE) {
        const firstKey = GLOBAL_COMMIT_DETAILS_CACHE.keys().next().value;
        if (firstKey) GLOBAL_COMMIT_DETAILS_CACHE.delete(firstKey);
      }
      GLOBAL_COMMIT_DETAILS_CACHE.set(cacheKey, result);
    } catch (error: any) {
      logger.warn(`Failed to fetch file commit details for ${repository}/${filePath}: ${error.message || error}`);
    }

    return result;
  }

  /**
   * Fetch a commit patch directly via HTTP GET without using GitHub API rate limit quota.
   * Parses the From: header and signed-off trailers to extract committer and author email.
   */
  async fetchCommitPatch(repository: string, commitSha: string): Promise<ExtractedCommitter[]> {
    return new Promise((resolve) => {
      const url = `https://github.com/${repository}/commit/${commitSha}.patch`;
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
          }
        },
        (res) => {
          if (res.statusCode !== 200) {
            resolve([]);
            return;
          }

          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
            // Committer header is at the top of the patch; if we exceed 10KB, we have enough metadata
            if (data.length > 10000) {
              res.destroy();
            }
          });

          res.on('close', () => {
            const committers = this.parsePatchForCommitter(data, commitSha);
            resolve(committers);
          });

          res.on('end', () => {
            const committers = this.parsePatchForCommitter(data, commitSha);
            resolve(committers);
          });
        }
      );

      req.on('error', (err) => {
        logger.debug(`Error fetching patch for ${repository}/commit/${commitSha}: ${err.message}`);
        resolve([]);
      });

      req.setTimeout(5000, () => {
        req.destroy();
        resolve([]);
      });
    });
  }

  /**
   * Parse email and author name from raw git patch text
   */
  parsePatchForCommitter(patchText: string, commitSha?: string): ExtractedCommitter[] {
    const results: ExtractedCommitter[] = [];
    const seen = new Set<string>();

    // Match "From: Full Name <email@domain.com>"
    const fromMatch = patchText.match(/^From:\s+([^<]+)<([^>]+)>/m);
    if (fromMatch) {
      const name = fromMatch[1].trim();
      const email = fromMatch[2].trim();
      if (isValidCommitterEmail(email)) {
        const cleaned = cleanCommitterEmail(email)!;
        seen.add(cleaned);
        results.push({ email: cleaned, name, commitSha });
      }
    }

    // Match "Signed-off-by: Full Name <email@domain.com>" or "Co-authored-by: ..."
    const trailerRegex = /^(?:Signed-off-by|Co-authored-by):\s+([^<]+)<([^>]+)>/gim;
    let match: RegExpExecArray | null;
    while ((match = trailerRegex.exec(patchText)) !== null) {
      const name = match[1].trim();
      const email = match[2].trim();
      if (isValidCommitterEmail(email)) {
        const cleaned = cleanCommitterEmail(email)!;
        if (!seen.has(cleaned)) {
          seen.add(cleaned);
          results.push({ email: cleaned, name, commitSha });
        }
      }
    }

    return results;
  }

  /**
   * Batched GraphQL query for file committers across multiple files.
   * Resolves up to 15 files in a SINGLE GraphQL request (1 rate limit point).
   */
  async batchGetFilesCommittersGraphQL(
    files: Array<{ repository: string; filePath: string }>
  ): Promise<Map<string, FileCommitDetails>> {
    const resultsMap = new Map<string, FileCommitDetails>();
    if (files.length === 0) return resultsMap;

    const queryParts: string[] = [];
    const validItems: Array<{ alias: string; repo: string; owner: string; name: string; path: string }> = [];

    files.forEach((item, index) => {
      const [owner, name] = item.repository.split('/');
      if (!owner || !name || !item.filePath) return;
      const alias = `f${index}`;
      validItems.push({ alias, repo: item.repository, owner, name, path: item.filePath });

      const escapedOwner = JSON.stringify(owner);
      const escapedName = JSON.stringify(name);
      const escapedPath = JSON.stringify(item.filePath);

      queryParts.push(`
        ${alias}: repository(owner: ${escapedOwner}, name: ${escapedName}) {
          defaultBranchRef {
            target {
              ... on Commit {
                history(first: 5, path: ${escapedPath}) {
                  nodes {
                    oid
                    committedDate
                    author { name email }
                    committer { name email }
                  }
                }
              }
            }
          }
        }
      `);
    });

    if (queryParts.length === 0) return resultsMap;

    const query = `query {\n${queryParts.join('\n')}\n}`;

    try {
      const response: any = await this.coreLimiter.schedule(() =>
        this.octokit.graphql(query)
      );

      if (response) {
        for (const item of validItems) {
          const key = `${item.repo}:${item.path}`;
          const repoData = response[item.alias];
          const historyNodes = repoData?.defaultBranchRef?.target?.history?.nodes;

          if (Array.isArray(historyNodes) && historyNodes.length > 0) {
            const committers: ExtractedCommitter[] = [];
            const seenEmails = new Set<string>();
            let primaryEmail: string | undefined;

            const latestNode = historyNodes[0];
            const commitSha = latestNode.oid;
            const commitDate = latestNode.committedDate ? new Date(latestNode.committedDate) : undefined;
            const commitUrl = `https://github.com/${item.repo}/commit/${commitSha}`;

            for (const node of historyNodes) {
              const nodeSha = node.oid;
              const nodeDate = node.committedDate ? new Date(node.committedDate) : undefined;

              if (isValidCommitterEmail(node.committer?.email)) {
                const cleaned = cleanCommitterEmail(node.committer.email)!;
                if (!seenEmails.has(cleaned)) {
                  seenEmails.add(cleaned);
                  committers.push({
                    email: cleaned,
                    name: node.committer.name,
                    commitSha: nodeSha,
                    commitDate: nodeDate
                  });
                  if (!primaryEmail) primaryEmail = cleaned;
                }
              }

              if (isValidCommitterEmail(node.author?.email)) {
                const cleaned = cleanCommitterEmail(node.author.email)!;
                if (!seenEmails.has(cleaned)) {
                  seenEmails.add(cleaned);
                  committers.push({
                    email: cleaned,
                    name: node.author.name,
                    commitSha: nodeSha,
                    commitDate: nodeDate
                  });
                  if (!primaryEmail) primaryEmail = cleaned;
                }
              }
            }

            resultsMap.set(key, {
              commitSha,
              commitDate,
              commitUrl,
              primaryEmail,
              committers
            });
          }
        }
      }
    } catch (error: any) {
      if (error.data) {
        for (const item of validItems) {
          const key = `${item.repo}:${item.path}`;
          const repoData = error.data[item.alias];
          const historyNodes = repoData?.defaultBranchRef?.target?.history?.nodes;
          if (Array.isArray(historyNodes) && historyNodes.length > 0) {
            const committers: ExtractedCommitter[] = [];
            const seenEmails = new Set<string>();
            let primaryEmail: string | undefined;

            const latestNode = historyNodes[0];
            const commitSha = latestNode.oid;
            const commitDate = latestNode.committedDate ? new Date(latestNode.committedDate) : undefined;
            const commitUrl = `https://github.com/${item.repo}/commit/${commitSha}`;

            for (const node of historyNodes) {
              const nodeSha = node.oid;
              const nodeDate = node.committedDate ? new Date(node.committedDate) : undefined;

              if (isValidCommitterEmail(node.committer?.email)) {
                const cleaned = cleanCommitterEmail(node.committer.email)!;
                if (!seenEmails.has(cleaned)) {
                  seenEmails.add(cleaned);
                  committers.push({ email: cleaned, name: node.committer.name, commitSha: nodeSha, commitDate: nodeDate });
                  if (!primaryEmail) primaryEmail = cleaned;
                }
              }

              if (isValidCommitterEmail(node.author?.email)) {
                const cleaned = cleanCommitterEmail(node.author.email)!;
                if (!seenEmails.has(cleaned)) {
                  seenEmails.add(cleaned);
                  committers.push({ email: cleaned, name: node.author.name, commitSha: nodeSha, commitDate: nodeDate });
                  if (!primaryEmail) primaryEmail = cleaned;
                }
              }
            }

            resultsMap.set(key, { commitSha, commitDate, commitUrl, primaryEmail, committers });
          }
        }
      } else {
        logger.warn(`GraphQL batch error for ${files.length} files: ${error.message || error}`);
      }
    }

    return resultsMap;
  }

  /**
   * Handle rate limit errors
   */
  private async handleRateLimitError(error: any): Promise<void> {
    const resetTime = error.response?.headers['x-ratelimit-reset'];

    if (resetTime) {
      const resetDate = new Date(parseInt(resetTime) * 1000);
      const waitTime = resetDate.getTime() - Date.now();

      if (waitTime > 0) {
        logger.warn(`Rate limit hit. Waiting ${waitTime / 1000}s until ${resetDate}`);
        await new Promise(resolve => setTimeout(resolve, waitTime + 1000));
      }
    } else {
      // Default wait time if no reset time provided
      logger.warn('Rate limit hit. Waiting 60s...');
      await new Promise(resolve => setTimeout(resolve, 60000));
    }
  }
}

export default GitHubService;
