# GITHUBRECON

A comprehensive platform for detecting sensitive information and security vulnerabilities in public GitHub repositories. This platform helps organizations monitor their domains, email addresses, API keys, credentials, and other sensitive data that may have been accidentally exposed on GitHub.

## Features

### 🔍 Comprehensive Scanning
- **Multi-source scanning**: Repositories, commits, issues, and gists
- **20+ secret types detected**: AWS keys, GitHub tokens, API keys, database URLs, private keys, and more
- **Domain monitoring**: Track mentions of your domains and email addresses
- **Pattern matching**: Advanced regex patterns with entropy analysis for accurate detection

### 📊 Intelligent Scoring
- **Criticality levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Smart scoring algorithm**: Based on secret type, entropy, context, repository popularity, and recency
- **False positive detection**: Automatically filters common test/example patterns
- **Context analysis**: Examines surrounding code for production/staging indicators

### 📈 Dashboard & Reporting
- **Visual analytics**: Charts showing findings by criticality, type, and repository
- **Real-time monitoring**: Track scan status and findings as they occur
- **Detailed findings view**: Full context, code snippets, and GitHub links
- **Bulk operations**: Mark multiple findings as verified or false positives

### 🔒 Security Features
- **Hashed storage**: Sensitive data is hashed before storage
- **Access control**: User-based authentication and authorization
- **Rate limiting**: Respect GitHub API limits with intelligent throttling
- **Audit logging**: Track all scanning activities

## Architecture

```
┌─────────────────┐
│   Frontend      │  React + TypeScript + TailwindCSS
│   (Port 5173)   │  - Dashboard with analytics
└────────┬────────┘  - Findings management
         │           - Domain configuration
         │
    ┌────▼──────────────────┐
    │   Backend API          │  Express + TypeScript
    │   (Port 3001)          │  - REST API endpoints
    └────┬──────────┬────────┘  - Authentication
         │          │           - Scan orchestration
         │          │
    ┌────▼──────┐   │
    │ SQLite    │   │
    │ Database  │   │
    └───────────┘   │
         │          │
         └──────────┘
                  │
         ┌────────▼──────────┐
         │  GitHub API       │
         │  Scanner Service  │
         └───────────────────┘
```

## Tech Stack

### Backend
- **Runtime**: Node.js 20+ with TypeScript
- **Framework**: Express.js
- **Database**: SQLite with Prisma ORM (configurable to PostgreSQL)
- **GitHub API**: Octokit with rate limiting (Bottleneck)

### Frontend
- **Framework**: React 18 with TypeScript
- **Styling**: TailwindCSS
- **State Management**: TanStack Query (React Query)
- **Charts**: Recharts
- **Build Tool**: Vite

### DevOps
- **Logging**: Winston
- **API Documentation**: REST with OpenAPI-ready structure

## Quick Start

### Prerequisites

- Node.js (v18+)
- GitHub Personal Access Token ([Create one here](https://github.com/settings/tokens))
  - Required scopes: `public_repo`, `read:user`

### Installation

1. **Clone the repository**
```bash
cd GitHubRecon
```

2. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` and add your GitHub token:
```env
GITHUB_TOKEN=your_github_personal_access_token_here
```

3. **Start the application**
```bash
./run-local.sh
```

This will start:
- Local SQLite database (`dev.db`)
- Backend API (port 3001)
- Frontend web app (port 5173)

4. **Access the application**
- Frontend: http://localhost:5173
- Backend API: http://localhost:3001/api
- API Health Check: http://localhost:3001/api/health

### Manual Setup (Step-by-Step)

1. **Install dependencies**
```bash
# Root
npm install

# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

2. **Setup database**
```bash
cd backend
npx prisma generate
npx prisma db push
```

3. **Start services**

In separate terminals:
```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev
```

## Usage Guide

### 1. Add a Domain

1. Navigate to the **Domains** page
2. Click **Add Domain**
3. Enter your domain (e.g., `company.com`)
4. Select scan frequency (manual, hourly, daily, weekly)
5. Click **Add Domain**

### 2. Start a Scan

1. Go to the **Domains** page
2. Click **Scan** on the domain you want to scan
3. Monitor scan progress on the **Dashboard**
4. View results in the **Findings** page

### 3. Review Findings

1. Navigate to **Findings**
2. Filter by:
   - **Criticality**: CRITICAL, HIGH, MEDIUM, LOW, INFO
   - **Type**: AWS keys, API keys, passwords, etc.
   - **Search**: Repository name, file path, content
3. For each finding:
   - View code context
   - Open in GitHub
   - Mark as verified or false positive
   - Add notes

### 4. Analyze Dashboard

The dashboard provides:
- **Total findings count**
- **Critical issues** requiring immediate attention
- **Pie chart**: Distribution by criticality
- **Bar chart**: Top repositories with findings
- **Recent scans** table with status

## Secret Types Detected

The platform detects 20+ types of secrets:

| Type | Example Pattern | Criticality Weight |
|------|----------------|-------------------|
| AWS Secret Key | `aws_secret: wJalrXUtnFEMI...` | 40/40 (Highest) |
| Private Key | `-----BEGIN PRIVATE KEY-----` | 40/40 |
| Database URL | `postgresql://user:pass@host/db` | 38/40 |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | 36/40 |
| Stripe API Key | `sk_live_...` | 35/40 |
| GitHub Token | `ghp_...` | 32/40 |
| Slack Token | `xoxb-...` | 30/40 |
| Google API Key | `AIza...` | 28/40 |
| SendGrid Key | `SG....` | 26/40 |
| JWT Token | `eyJ...` | 20/40 |
| Generic Secret | `api_key: value` | 12/40 |
| Email | `user@domain.com` | 6/40 |
| Domain | `subdomain.domain.com` | 4/40 |

## Criticality Scoring

Findings are scored 0-100 based on multiple factors:

### Scoring Components (Total: 100 points)

1. **Secret Type** (40 points)
   - AWS keys, private keys: 40 pts
   - API keys, tokens: 20-35 pts
   - Emails, domains: 4-6 pts

2. **Entropy** (25 points)
   - High entropy = more random = likely real secret
   - Calculated using Shannon entropy
   - Threshold varies by secret type

3. **Context Analysis** (20 points)
   - Production keywords: +15 pts
   - Environment variables: +8 pts
   - Comments/documentation: -5 pts

4. **Repository Reputation** (10 points)
   - Based on stars and forks
   - More popular = higher exposure risk

5. **Recency** (5 points)
   - Last week: 5 pts
   - Last month: 4 pts
   - Last year: 2 pts

### Criticality Levels

- **CRITICAL (90-100)**: Immediate action required. Active credentials exposing production systems.
- **HIGH (75-89)**: High priority. Valid secrets that should be rotated immediately.
- **MEDIUM (50-74)**: Medium priority. Potential credentials requiring review.
- **LOW (25-49)**: Low priority. Informational findings.
- **INFO (0-24)**: Informational. General mentions or low-confidence matches.

## API Endpoints

### Domains
```
GET    /api/domains              - List all domains
POST   /api/domains              - Create new domain
GET    /api/domains/:id          - Get domain details
PUT    /api/domains/:id          - Update domain
DELETE /api/domains/:id          - Delete domain
```

### Scans
```
GET    /api/scans                - List all scans
POST   /api/scans                - Create new scan
GET    /api/scans/:id            - Get scan details
DELETE /api/scans/:id            - Cancel scan
GET    /api/scans/:id/findings   - Get scan findings
```

### Findings
```
GET    /api/findings             - List all findings (with filters)
GET    /api/findings/stats       - Get statistics
GET    /api/findings/:id         - Get finding details
PUT    /api/findings/:id         - Update finding
POST   /api/findings/bulk-update - Bulk update findings
DELETE /api/findings/:id         - Delete finding
```

## Configuration

### Environment Variables

#### Backend
```env
NODE_ENV=development              # Environment
PORT=3001                         # API port

DATABASE_URL="file:./dev.db"      # SQLite connection

GITHUB_TOKEN=ghp_...              # GitHub API token

RATE_LIMIT_WINDOW_MS=60000        # Rate limit window
RATE_LIMIT_MAX_REQUESTS=100       # Max requests per window

FRONTEND_URL=http://localhost:5173 # CORS origin
LOG_LEVEL=info                     # Logging level
```

#### Frontend
```env
VITE_API_URL=http://localhost:3001  # Backend API URL
```

### GitHub Rate Limits

The platform respects GitHub API rate limits:
- **Authenticated**: 5,000 requests/hour
- **Code Search**: 30 requests/minute (most restrictive)

**Strategies**:
- Intelligent throttling with exponential backoff
- Results caching (1 hour)
- Distributed queries over time
- Multiple token support (round-robin)

## Development

### Project Structure

```
GitHubRecon/
├── backend/
│   ├── src/
│   │   ├── config/          # Database, Redis config
│   │   ├── controllers/     # Route handlers
│   │   ├── services/        # Business logic
│   │   │   ├── github.service.ts    # GitHub API integration
│   │   │   ├── scanner.service.ts   # Scan orchestration
│   │   │   └── scoring.service.ts   # Criticality scoring
│   │   ├── utils/
│   │   │   ├── patterns.ts          # Secret patterns (20+ types)
│   │   │   └── logger.ts            # Winston logger
│   │   ├── middleware/      # Auth, error handling
│   │   ├── routes/          # API routes
│   │   └── server.ts        # Express app
│   ├── prisma/
│   │   └── schema.prisma    # Database schema
│   └── package.json
│
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── pages/           # Page components
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Findings.tsx
│   │   │   └── Domains.tsx
│   │   ├── lib/
│   │   │   └── api.ts       # API client
│   │   └── main.tsx
│   └── package.json
│
└── README.md                # Documentation
```

### Adding New Secret Patterns

Edit `/backend/src/utils/patterns.ts`:

```typescript
{
  type: 'MY_SECRET_TYPE',
  pattern: /your-regex-pattern/g,
  description: 'Description of the secret',
  entropyThreshold: 3.5,
  contextKeywords: ['keyword1', 'keyword2'],
  exampleMatch: 'example-value'
}
```

### Running Tests

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test
```

## Troubleshooting

### Issue: "Rate limit exceeded"
**Solution**:
- Wait for rate limit to reset (shown in error message)
- Add more GitHub tokens in `.env`
- Reduce scan frequency

### Issue: "Database connection failed"
**Solution**:
- Ensure the database file or service is accessible
- Check `DATABASE_URL` in `.env`
- Run `npx prisma db push` to sync schema

### Issue: "No findings returned"
**Solution**:
- Verify GitHub token has correct scopes
- Check if domain exists in public repositories

### Issue: "Frontend can't connect to backend"
**Solution**:
- Verify backend is running on port 3001
- Check CORS settings in backend
- Update `VITE_API_URL` in frontend `.env`

## Security Considerations

### For Production Deployment

1. **Environment Configuration**
   - Use environment-specific values for production configuration

2. **Enable HTTPS**
   - Use SSL certificates (Let's Encrypt)
   - Update CORS origins

3. **Database security**
   - If using PostgreSQL in production, use strong passwords
   - Enable SSL for database connections
   - Regular backups

4. **API key management**
   - Rotate GitHub tokens regularly
   - Use separate tokens for different environments
   - Monitor token usage

5. **Access control**
   - Implement proper authentication
   - Add role-based access control (RBAC)
   - Enable audit logging

6. **Data retention**
   - Configure finding retention policies
   - Regularly clean old scan data
   - GDPR compliance for email data

## Performance Optimization

### For Large-Scale Deployments

1. **Database**
   - Add indexes on frequently queried fields
   - Use connection pooling
   - Consider read replicas

2. **Caching**
   - Redis for scan results (1 hour TTL)
   - API response caching
   - Frontend query caching

3. **Queue Management**
   - Scale queue workers horizontally
   - Priority queues for critical scans
   - Dead letter queues for failures

4. **Search Optimization**
   - ElasticSearch for findings search
   - Full-text search indexes
   - Pagination for large result sets

## Roadmap

### Upcoming Features

- [ ] **Authentication**: User registration and login
- [ ] **Scheduled scans**: Automatic scanning based on frequency
- [ ] **Email notifications**: Alert on critical findings
- [ ] **Webhook support**: Integrate with SIEM/ticketing systems
- [ ] **ML-based detection**: Reduce false positives
- [ ] **Team workspaces**: Multi-user collaboration

## Contributing

Contributions are welcome! Areas for improvement:

1. **New secret patterns**: Add detection for more secret types
2. **Scoring improvements**: Enhance criticality algorithm
3. **UI/UX**: Improve dashboard and findings visualization
4. **Documentation**: Expand guides and API docs
5. **Tests**: Increase test coverage
6. **Performance**: Optimize scanning speed

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or feature requests:
- Create an issue on GitHub
- Check existing documentation
- Review troubleshooting guide above

## Acknowledgments

- Built with [Octokit](https://github.com/octokit/rest.js) for GitHub API
- Inspired by tools like TruffleHog and GitGuardian
- Secret patterns based on community research

---

**⚠️ Important**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning domains and repositories. Respect GitHub's Terms of Service and rate limits.
