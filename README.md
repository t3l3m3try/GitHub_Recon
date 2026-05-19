# GitHub Recon

A platform for detecting sensitive information and security vulnerabilities in public GitHub repositories. GitHub Recon helps organizations monitor their domains, email addresses, API keys, credentials, and other sensitive data that may have been accidentally exposed.

<img width="1372" height="911" alt="1" src="https://github.com/user-attachments/assets/233b0aa3-172f-48f5-a894-1fbd1a3ace30" />


## 🚀 Key Features

- **Comprehensive Scanning**: Monitors repositories, commits, issues, and gists for exposed data.
- **20+ Secret Types Detected**: Automatically identifies AWS keys, GitHub tokens, database URLs, and private keys.
- **Intelligent Scoring**: Ranks findings by criticality (CRITICAL, HIGH, MEDIUM, LOW, INFO) using entropy analysis and surrounding context.
- **Professional SOC Dashboard**: Features a newly designed dark-mode, Security Operations Center (SOC) style UI for clear analytics, reporting, and finding management.

## 🛠️ Tech Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS, Recharts
- **Backend**: Node.js, Express.js, TypeScript
- **Database**: SQLite with Prisma ORM
- **API**: GitHub REST API (Octokit)

## 🏁 Quick Start

### Prerequisites
- Node.js (v18+)
- GitHub Personal Access Token (requires `public_repo`, `read:user` scopes)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/t3l3m3try/GitHub_Recon.git
   cd GitHub_Recon
   ```

2. **Configure your environment:**
   ```bash
   cp .env.example .env
   ```
   Edit the `.env` file and add your GitHub token:
   ```env
   GITHUB_TOKEN=your_github_personal_access_token_here
   ```

3. **Install and Run:**
   The project includes a convenient script to install dependencies, set up the database, and start both the frontend and backend simultaneously:
   ```bash
   ./run-local.sh
   ```

4. **Access the platform:**
   Open [http://localhost:5173](http://localhost:5173) in your browser.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request to help improve secret detection patterns, UI/UX, or backend performance.

## 📄 License

MIT License - see the LICENSE file for details.

---

**⚠️ Important**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning domains and repositories. Respect GitHub's Terms of Service and rate limits.
