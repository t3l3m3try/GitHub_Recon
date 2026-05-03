import { Octokit } from '@octokit/rest';
import Bottleneck from 'bottleneck';
import { logger } from '../utils/logger';


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

class GitHubService {
  private octokit: Octokit;
  private limiter: Bottleneck;       // Search API: 30 req/min (strict GitHub limit)
  private coreLimiter: Bottleneck;   // Core API (blobs, repos): 5000 req/hour

  constructor(token: string) {
    this.octokit = new Octokit({
      auth: token,
      userAgent: 'GitHub-CTI-Monitor/1.0'
    });

    // Search API rate limiter — GitHub enforces 30 requests/min for code search
    this.limiter = new Bottleneck({
      reservoir: 30,
      reservoirRefreshAmount: 30,
      reservoirRefreshInterval: 60 * 1000,
      maxConcurrent: 3,  // Reduced from 5 to limit peak parallel queries
      minTime: 2000
    });

    // Core API rate limiter — GitHub allows 5000 requests/hour (~83/min)
    // Used for blob fetches which are NOT subject to the search rate limit
    this.coreLimiter = new Bottleneck({
      reservoir: 80,
      reservoirRefreshAmount: 80,
      reservoirRefreshInterval: 60 * 1000,
      maxConcurrent: 3, // Reduced from 10 to flatten CPU load during heavy blob parsing
      minTime: 500      // Decreased to speed up parallel blob fetching
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
      const { perPage = 30, page = 1, sort, order, retries = 3 } = options;

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

      const results: SearchResult[] = [];

      for (const item of response.data.items) {
        try {
          // Use blob API with item.sha (blob SHA) — getContent with blob SHA returns 404
          const content = await this.getBlobContent(
            item.repository.owner.login,
            item.repository.name,
            item.sha
          );

          results.push({
            repository: item.repository.full_name,
            repositoryUrl: item.repository.html_url,
            filePath: item.path,
            content,
            sha: item.sha,
            htmlUrl: item.html_url,
          });
        } catch (error) {
          logger.error(`Error fetching content for ${item.path}:`, error);
        }
      }

      return results;
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
      const { perPage = 30, page = 1, retries = 3 } = options;

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
      const { perPage = 30, page = 1, retries = 3 } = options;

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
    try {
      const response = await this.coreLimiter.schedule(() =>
        this.octokit.rest.git.getBlob({
          owner,
          repo,
          file_sha: blobSha
        })
      );

      if (response.data.encoding === 'base64') {
        return Buffer.from(response.data.content, 'base64').toString('utf-8');
      }
      return response.data.content;
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
    try {
      const [owner, repo] = repository.split('/');
      const response = await this.coreLimiter.schedule(() =>
        this.octokit.rest.repos.listCommits({
          owner,
          repo,
          path: filePath,
          per_page: 1
        })
      );
      if (response.data.length > 0) {
        const commit = response.data[0];
        const dateStr = commit.commit.committer?.date || commit.commit.author?.date;
        if (dateStr) {
          const date = new Date(dateStr);
          logger.info(`File date fetched: ${repository}/${filePath} → ${date.toISOString()}`);
          return date;
        }
      }
      logger.warn(`No commit date found for ${repository}/${filePath}`);
      return undefined;
    } catch (error: any) {
      logger.warn(`Failed to fetch file date for ${repository}/${filePath}: ${error.message || error}`);
      return undefined; // Non-fatal — just skip the date
    }
  }

  /**
   * Get rate limit status
   */
  async getRateLimit(): Promise<{
    limit: number;
    remaining: number;
    reset: Date;
    used: number;
  }> {
    try {
      const response = await this.octokit.rest.rateLimit.get();
      const core = response.data.resources.core;
      const search = response.data.resources.search;

      return {
        limit: search.limit,
        remaining: search.remaining,
        reset: new Date(search.reset * 1000),
        used: search.used
      };
    } catch (error) {
      logger.error('Error getting rate limit:', error);
      throw error;
    }
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

  /**
   * Check if token is valid
   */
  async validateToken(): Promise<boolean> {
    try {
      await this.octokit.rest.users.getAuthenticated();
      return true;
    } catch (error) {
      logger.error('Token validation failed:', error);
      return false;
    }
  }
}

export default GitHubService;
