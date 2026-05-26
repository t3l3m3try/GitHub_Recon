import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { findingsAPI, domainAPI, Finding } from '../lib/api';
import { ExternalLink, Check, X, Search, Filter, Download, ChevronDown, ChevronUp } from 'lucide-react';

// Badge styles per criticality — using inline styles to bypass all Tailwind/Vite caching issues
const CRITICALITY_BADGE_STYLES: Record<string, React.CSSProperties> = {
  CRITICAL: { backgroundColor: 'rgba(239,68,68,0.2)', color: '#fca5a5', borderColor: 'rgba(239,68,68,0.6)' },
  HIGH: { backgroundColor: 'rgba(249,115,22,0.2)', color: '#fdba74', borderColor: 'rgba(249,115,22,0.6)' },
  MEDIUM: { backgroundColor: 'rgba(234,179,8,0.2)', color: '#fde047', borderColor: 'rgba(234,179,8,0.6)' },
  LOW: { backgroundColor: 'rgba(6,182,212,0.2)', color: '#93C5FD', borderColor: 'rgba(6,182,212,0.6)' },
  INFO: { backgroundColor: 'rgba(55,65,81,0.3)', color: '#d1d5db', borderColor: 'rgba(107,114,128,0.3)' },
};

// Card styles per criticality — uniform background, only border color changes
const CRITICALITY_CARD_STYLES: Record<string, React.CSSProperties> = {
  CRITICAL: { borderColor: 'rgba(239,68,68,0.4)' },
  HIGH: { borderColor: 'rgba(249,115,22,0.4)' },
  MEDIUM: { borderColor: 'rgba(234,179,8,0.3)' },
  LOW: { borderColor: 'rgba(6,182,212,0.3)' },
  INFO: { borderColor: 'rgba(107,114,128,0.3)' },
};

// Escape HTML to prevent injected stylesheets from finding content/context
const escapeHtml = (text: string) =>
  text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

// Helper function to highlight search terms (HTML-safe)
const highlightText = (text: string, searchTerm: string) => {
  const escaped = escapeHtml(text);
  if (!searchTerm) return escaped;

  const parts = escaped.split(new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'));
  return parts.map((part) =>
    part.toLowerCase() === searchTerm.toLowerCase()
      ? `<mark class="bg-yellow-400 text-black font-bold px-1 rounded">${part}</mark>`
      : part
  ).join('');
};

export default function Findings() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    criticality: searchParams.get('criticality') || '',
    type: searchParams.get('type') || '',
    domain: searchParams.get('domain') || '',
    search: searchParams.get('search') || '',
    repository: searchParams.get('repository') || '',
    scanId: searchParams.get('scanId') || '',
    status: searchParams.get('status') || '',   // '' | 'verified' | 'false_positive' | 'unreviewed'
  });
  const [searchInput, setSearchInput] = useState(searchParams.get('search') || '');
  const [exporting, setExporting] = useState<'csv' | 'json' | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  const toggleExpand = (findingId: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
      } else {
        next.add(findingId);
      }
      return next;
    });
  };

  // Sync ALL URL param changes (e.g. when navigating from Dashboard)
  useEffect(() => {
    const crit = searchParams.get('criticality') || '';
    const type = searchParams.get('type') || '';
    const domain = searchParams.get('domain') || '';
    const repo = searchParams.get('repository') || '';
    const scanId = searchParams.get('scanId') || '';
    const search = searchParams.get('search') || '';
    const status = searchParams.get('status') || '';

    setFilters({ criticality: crit, type, domain, repository: repo, scanId, search, status });
    if (search) setSearchInput(search);
    setPage(1);
  }, [searchParams]);

  // Fetch domains for filter dropdown
  const { data: domainsData } = useQuery({
    queryKey: ['domains'],
    queryFn: async () => {
      const response = await domainAPI.getAll();
      return response.data;
    },
  });

  const { data, isLoading } = useQuery({
    queryKey: ['findings', page, filters.criticality, filters.type, filters.domain, filters.search, filters.repository, filters.scanId, filters.status],
    queryFn: async () => {
      const params: any = { page, limit: 20 };
      if (filters.criticality) params.criticality = filters.criticality;
      if (filters.type) params.type = filters.type;
      if (filters.domain) params.domain = filters.domain;
      if (filters.search) params.search = filters.search;
      if (filters.repository) params.repository = filters.repository;
      if (filters.scanId) params.scanId = filters.scanId;
      // Status filter → maps to verified / falsePositive boolean params
      if (filters.status === 'verified') { params.verified = 'true'; params.falsePositive = 'false'; }
      if (filters.status === 'false_positive') { params.falsePositive = 'true'; }
      if (filters.status === 'unreviewed') { params.verified = 'false'; params.falsePositive = 'false'; }
      const response = await findingsAPI.getAll(params);
      return response.data;
    },
  });

  const exportData = async (format: 'csv' | 'json') => {
    try {
      setExporting(format);

      // Fetch all data matching current filters, ignoring pagination
      const params: any = { limit: 10000 };
      if (filters.criticality) params.criticality = filters.criticality;
      if (filters.type) params.type = filters.type;
      if (filters.domain) params.domain = filters.domain;
      if (filters.search) params.search = filters.search;
      if (filters.repository) params.repository = filters.repository;
      if (filters.scanId) params.scanId = filters.scanId;
      if (filters.status === 'verified') { params.verified = 'true'; params.falsePositive = 'false'; }
      if (filters.status === 'false_positive') { params.falsePositive = 'true'; }
      if (filters.status === 'unreviewed') { params.verified = 'false'; params.falsePositive = 'false'; }

      const response = await findingsAPI.getAll(params);
      const findings = response.data.findings || [];

      let blob;
      if (format === 'json') {
        blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
      } else {
        // CSV encoding
        const escapeCsv = (str: string | number | null | undefined) => {
          if (str === null || str === undefined) return '""';
          const stringified = String(str);
          // If contains comma, newline, or double quote, wrap in quotes and escape internal quotes
          if (/[,"\n\r]/.test(stringified)) {
            return `"${stringified.replace(/"/g, '""')}"`;
          }
          return stringified;
        };

        const headers = ['scanId', 'findingId', 'secretId', 'type', 'criticality', 'content', 'repository', 'repositoryUrl', 'fileUrl', 'commitDate', 'Status', 'score'];
        const csvRows = [headers.join(',')];

        for (const f of findings) {
          let status = 'Unreviewed';
          if (f.verified) status = 'Verified';
          if (f.falsePositive) status = 'False Positive';

          for (const s of f.secrets || []) {
            const row = [
              f.scanId,
              f.id,
              s.id,
              s.type,
              s.criticality,
              s.content || '',
              f.repository,
              f.repositoryUrl || '',
              f.fileUrl || '',
              f.commitDate ? new Date(f.commitDate).toLocaleString() : '',
              status,
              f.score
            ].map(escapeCsv);

            csvRows.push(row.join(','));
          }
        }

        blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `github-recon-findings-${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export data', error);
      alert('Failed to export data. Check console for details.');
    } finally {
      setExporting(null);
    }
  };

  // Helper to clear a specific URL param filter
  const clearUrlFilter = (key: string) => {
    const newParams = new URLSearchParams(searchParams);
    newParams.delete(key);
    setSearchParams(newParams);
  };

  // Active URL-driven filters (repository and scanId shown as dismissible chips)
  const activeRepository = filters.repository;
  const activeScanId = filters.scanId;

  const handleSearch = () => {
    setFilters({ ...filters, search: searchInput });
    setPage(1);
    // Keep URL in sync — preserve other params
    const newParams = new URLSearchParams(searchParams);
    if (searchInput) newParams.set('search', searchInput);
    else newParams.delete('search');
    setSearchParams(newParams);
  };

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Finding> }) =>
      findingsAPI.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const handleMarkFalsePositive = (finding: Finding) => {
    updateMutation.mutate({
      id: finding.id,
      data: { falsePositive: !finding.falsePositive },
    });
  };

  const handleMarkVerified = (finding: Finding) => {
    updateMutation.mutate({
      id: finding.id,
      data: { verified: !finding.verified },
    });
  };

  const getCriticalityIcon = (criticality: string) => {
    switch (criticality) {
      case 'CRITICAL':
        return '🔴';
      case 'HIGH':
        return '🟠';
      case 'MEDIUM':
        return '🟡';
      case 'LOW':
        return '🔵';
      default:
        return '⚪';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-gray-400 animate-subtle-pulse">Loading findings...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold mb-1 page-title">Findings</h2>
        <p className="text-gray-400 text-sm">Discovered security findings from GitHub scans</p>
      </div>

      {/* Filters */}
      <div className="card" style={{ borderColor: 'rgba(59,130,246,0.15)' }}>
        {/* Active URL-driven filter chips */}
        {(activeRepository || activeScanId || filters.search) && (
          <div className="flex flex-wrap gap-2 mb-4">
            <span className="flex items-center text-gray-500 text-xs uppercase tracking-wider mr-1">
              <Filter className="w-3 h-3 mr-1" /> Active filters:
            </span>
            {activeRepository && (
              <span className="flex items-center gap-1 px-2 py-1 rounded-md text-xs text-gray-300 font-mono" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
                📂 {activeRepository.length > 35 ? `...${activeRepository.slice(-32)}` : activeRepository}
                <button onClick={() => clearUrlFilter('repository')} className="ml-1 text-gray-400 hover:text-white transition-colors">×</button>
              </span>
            )}
            {activeScanId && (
              <span className="flex items-center gap-1 px-2 py-1 rounded-md text-xs text-gray-300 font-mono" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
                🔍 Scan filter
                <button onClick={() => clearUrlFilter('scanId')} className="ml-1 text-gray-400 hover:text-white transition-colors">×</button>
              </span>
            )}
            {filters.search && (
              <span className="flex items-center gap-1 px-2 py-1 rounded-md text-xs text-gray-300 font-mono" style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.15)' }}>
                🔎 "{filters.search.length > 30 ? filters.search.substring(0, 30) + '…' : filters.search}"
                <button onClick={() => { clearUrlFilter('search'); setFilters(f => ({ ...f, search: '' })); setSearchInput(''); }} className="ml-1 text-gray-400 hover:text-white transition-colors">×</button>
              </span>
            )}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-4">
          <div>
            <label className="block text-xs text-gray-400 mb-2 uppercase tracking-wider font-semibold">Criticality</label>
            <select
              className="input"
              value={filters.criticality}
              onChange={(e) => {
                const val = e.target.value;
                setFilters({ ...filters, criticality: val });
                setPage(1);
                // Keep URL in sync — preserve other params (repository, scanId, search)
                const newParams = new URLSearchParams(searchParams);
                if (val) newParams.set('criticality', val);
                else newParams.delete('criticality');
                setSearchParams(newParams);
              }}
            >
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-2 uppercase tracking-wider font-semibold">Type</label>
            <select
              className="input"
              value={filters.type}
              onChange={(e) => { setFilters({ ...filters, type: e.target.value }); setPage(1); }}
            >
              <option value="">All Types</option>
              <optgroup label="Email">
                <option value="EMAIL">Email</option>
              </optgroup>
              <optgroup label="AWS">
                <option value="AWS_ACCESS_KEY">AWS Access Key</option>
                <option value="AWS_SECRET_KEY">AWS Secret Key</option>
              </optgroup>
              <optgroup label="Version Control">
                <option value="GITHUB_TOKEN">GitHub Token</option>
                <option value="GITLAB_TOKEN">GitLab Token</option>
                <option value="BITBUCKET_TOKEN">Bitbucket Token</option>
              </optgroup>
              <optgroup label="Cloud & APIs">
                <option value="API_KEY">API Key</option>
                <option value="GOOGLE_API_KEY">Google API Key</option>
                <option value="FIREBASE_KEY">Firebase Key</option>
                <option value="AZURE_KEY">Azure Key</option>
                <option value="HEROKU_KEY">Heroku Key</option>
                <option value="CLOUDFLARE_KEY">Cloudflare Key</option>
              </optgroup>
              <optgroup label="Credentials">
                <option value="CREDENTIAL_PAIR">Credential Pair (Email+Pass)</option>
                <option value="PASSWORD">Password</option>
                <option value="OAUTH_TOKEN">OAuth Token</option>
                <option value="BEARER_TOKEN">Bearer Token</option>
                <option value="JWT_SECRET">JWT Token</option>
              </optgroup>
              <optgroup label="Keys & Certificates">
                <option value="PRIVATE_KEY">Private Key</option>
                <option value="SSH_KEY">SSH Key</option>
                <option value="PGP_KEY">PGP Private Key</option>
              </optgroup>
              <optgroup label="Payment Systems">
                <option value="STRIPE_KEY">Stripe Key</option>
                <option value="SQUARE_KEY">Square Key</option>
                <option value="PAYPAL_TOKEN">PayPal Token</option>
              </optgroup>
              <optgroup label="Communication">
                <option value="SLACK_TOKEN">Slack Token</option>
                <option value="SLACK_WEBHOOK">Slack Webhook</option>
                <option value="SENDGRID_KEY">SendGrid Key</option>
                <option value="MAILCHIMP_KEY">MailChimp Key</option>
                <option value="TWILIO_KEY">Twilio Key</option>
              </optgroup>
              <optgroup label="E-commerce">
                <option value="SHOPIFY_KEY">Shopify Key</option>
              </optgroup>
              <optgroup label="Database">
                <option value="DATABASE_URL">Database URL</option>
                <option value="CONNECTION_STRING">Connection String</option>
              </optgroup>
              <optgroup label="Development">
                <option value="NPMRC_AUTH">NPM Auth Token</option>
                <option value="NPM_TOKEN">NPM Token</option>
                <option value="DOCKER_PASSWORD">Docker Password</option>
              </optgroup>
              <optgroup label="Monitoring">
                <option value="DATADOG_KEY">Datadog Key</option>
              </optgroup>
              <optgroup label="Other">
                <option value="GENERIC_SECRET">Generic Secret</option>
              </optgroup>
              <optgroup label="Precision Sub-Variants">
                <option value="1PASSWORD_SECRET_KEY">1Password Secret Key</option>
                <option value="1PASSWORD_SERVICE_ACCOUNT_TOKEN">1Password Service Account Token</option>
                <option value="ADAFRUIT_API_KEY">Adafruit Api Key</option>
                <option value="ADOBE_CLIENT_ID">Adobe Client Id</option>
                <option value="ADOBE_CLIENT_SECRET">Adobe Client Secret</option>
                <option value="AGE_SECRET_KEY">Age Secret Key</option>
                <option value="AIRTABLE_API_KEY">Airtable Api Key</option>
                <option value="AIRTABLE_PERSONNAL_ACCESS_TOKEN">Airtable Personnal Access Token</option>
                <option value="ALGOLIA_API_KEY">Algolia Api Key</option>
                <option value="ALIBABA_ACCESS_KEY_ID">Alibaba Access Key Id</option>
                <option value="ALIBABA_SECRET_KEY">Alibaba Secret Key</option>
                <option value="ANTHROPIC_ADMIN_API_KEY">Anthropic Admin Api Key</option>
                <option value="ANTHROPIC_API_KEY">Anthropic Api Key</option>
                <option value="ARTIFACTORY_API_KEY">Artifactory Api Key</option>
                <option value="ARTIFACTORY_REFERENCE_TOKEN">Artifactory Reference Token</option>
                <option value="ASANA_CLIENT_ID">Asana Client Id</option>
                <option value="ASANA_CLIENT_SECRET">Asana Client Secret</option>
                <option value="ASSEMBLYAI_API_KEY">Assemblyai Api Key</option>
                <option value="ATLASSIAN_API_TOKEN">Atlassian Api Token</option>
                <option value="AUTHRESS_SERVICE_CLIENT_ACCESS_KEY">Authress Service Client Access Key</option>
                <option value="AWS_ACCESS_TOKEN">Aws Access Token</option>
                <option value="AWS_AMAZON_BEDROCK_API_KEY_LONG_LIVED">Aws Amazon Bedrock Api Key Long Lived</option>
                <option value="AWS_AMAZON_BEDROCK_API_KEY_SHORT_LIVED">Aws Amazon Bedrock Api Key Short Lived</option>
                <option value="AWS_SECRET_ACCESS_KEY">Aws Secret Access Key</option>
                <option value="AZURE_AD_CLIENT_SECRET">Azure Ad Client Secret</option>
                <option value="BEAMER_API_TOKEN">Beamer Api Token</option>
                <option value="BITBUCKET_CLIENT_ID">Bitbucket Client Id</option>
                <option value="BITBUCKET_CLIENT_SECRET">Bitbucket Client Secret</option>
                <option value="BITTREX_ACCESS_KEY">Bittrex Access Key</option>
                <option value="BITTREX_SECRET_KEY">Bittrex Secret Key</option>
                <option value="CEREBRAS_API_KEY">Cerebras Api Key</option>
                <option value="CISCO_MERAKI_API_KEY">Cisco Meraki Api Key</option>
                <option value="CLICKHOUSE_CLOUD_API_SECRET_KEY">Clickhouse Cloud Api Secret Key</option>
                <option value="CLOJARS_API_TOKEN">Clojars Api Token</option>
                <option value="CLOUDFLARE_API_KEY">Cloudflare Api Key</option>
                <option value="CLOUDFLARE_GLOBAL_API_KEY">Cloudflare Global Api Key</option>
                <option value="CLOUDFLARE_ORIGIN_CA_KEY">Cloudflare Origin Ca Key</option>
                <option value="CODECOV_ACCESS_TOKEN">Codecov Access Token</option>
                <option value="COHERE_API_TOKEN">Cohere Api Token</option>
                <option value="COINBASE_ACCESS_TOKEN">Coinbase Access Token</option>
                <option value="CONFLUENT_ACCESS_TOKEN">Confluent Access Token</option>
                <option value="CONFLUENT_SECRET_KEY">Confluent Secret Key</option>
                <option value="CONTENTFUL_DELIVERY_API_TOKEN">Contentful Delivery Api Token</option>
                <option value="CURL_AUTH_HEADER">Curl Auth Header</option>
                <option value="CURL_AUTH_USER">Curl Auth User</option>
                <option value="CURSOR_API_KEY">Cursor Api Key</option>
                <option value="DATABRICKS_API_TOKEN">Databricks Api Token</option>
                <option value="DATADOG_ACCESS_TOKEN">Datadog Access Token</option>
                <option value="DEEPGRAM_API_KEY">Deepgram Api Key</option>
                <option value="DEEPSEEK_API_KEY">Deepseek Api Key</option>
                <option value="DEFINED_NETWORKING_API_TOKEN">Defined Networking Api Token</option>
                <option value="DIGITALOCEAN_ACCESS_TOKEN">Digitalocean Access Token</option>
                <option value="DIGITALOCEAN_PAT">Digitalocean Pat</option>
                <option value="DIGITALOCEAN_REFRESH_TOKEN">Digitalocean Refresh Token</option>
                <option value="DISCORD_API_TOKEN">Discord Api Token</option>
                <option value="DISCORD_CLIENT_ID">Discord Client Id</option>
                <option value="DISCORD_CLIENT_SECRET">Discord Client Secret</option>
                <option value="DOPPLER_API_TOKEN">Doppler Api Token</option>
                <option value="DRONECI_ACCESS_TOKEN">Droneci Access Token</option>
                <option value="DROPBOX_API_TOKEN">Dropbox Api Token</option>
                <option value="DROPBOX_LONG_LIVED_API_TOKEN">Dropbox Long Lived Api Token</option>
                <option value="DROPBOX_SHORT_LIVED_API_TOKEN">Dropbox Short Lived Api Token</option>
                <option value="DUFFEL_API_TOKEN">Duffel Api Token</option>
                <option value="DYNATRACE_API_TOKEN">Dynatrace Api Token</option>
                <option value="EASYPOST_API_TOKEN">Easypost Api Token</option>
                <option value="EASYPOST_TEST_API_TOKEN">Easypost Test Api Token</option>
                <option value="ELEVENLABS_API_KEY">Elevenlabs Api Key</option>
                <option value="ENDORLABS_API_KEY">Endorlabs Api Key</option>
                <option value="ENDORLABS_API_SECRET">Endorlabs Api Secret</option>
                <option value="ETSY_ACCESS_TOKEN">Etsy Access Token</option>
                <option value="FACEBOOK_ACCESS_TOKEN">Facebook Access Token</option>
                <option value="FACEBOOK_PAGE_ACCESS_TOKEN">Facebook Page Access Token</option>
                <option value="FACEBOOK_SECRET">Facebook Secret</option>
                <option value="FASTLY_API_TOKEN">Fastly Api Token</option>
                <option value="FINICITY_API_TOKEN">Finicity Api Token</option>
                <option value="FINICITY_CLIENT_SECRET">Finicity Client Secret</option>
                <option value="FINNHUB_ACCESS_TOKEN">Finnhub Access Token</option>
                <option value="FLICKR_ACCESS_TOKEN">Flickr Access Token</option>
                <option value="FLUTTERWAVE_ENCRYPTION_KEY">Flutterwave Encryption Key</option>
                <option value="FLUTTERWAVE_PUBLIC_KEY">Flutterwave Public Key</option>
                <option value="FLUTTERWAVE_SECRET_KEY">Flutterwave Secret Key</option>
                <option value="FLYIO_ACCESS_TOKEN">Flyio Access Token</option>
                <option value="FRAMEIO_API_TOKEN">Frameio Api Token</option>
                <option value="FREEMIUS_SECRET_KEY">Freemius Secret Key</option>
                <option value="FRESHBOOKS_ACCESS_TOKEN">Freshbooks Access Token</option>
                <option value="GCP_API_KEY">Gcp Api Key</option>
                <option value="GITEA_ACCESS_TOKEN">Gitea Access Token</option>
                <option value="GITHUB_APP_TOKEN">Github App Token</option>
                <option value="GITHUB_FINE_GRAINED_PAT">Github Fine Grained Pat</option>
                <option value="GITHUB_OAUTH">Github Oauth</option>
                <option value="GITHUB_PAT">Github Pat</option>
                <option value="GITHUB_REFRESH_TOKEN">Github Refresh Token</option>
                <option value="GITLAB_CICD_JOB_TOKEN">Gitlab Cicd Job Token</option>
                <option value="GITLAB_DEPLOY_TOKEN">Gitlab Deploy Token</option>
                <option value="GITLAB_FEATURE_FLAG_CLIENT_TOKEN">Gitlab Feature Flag Client Token</option>
                <option value="GITLAB_FEED_TOKEN">Gitlab Feed Token</option>
                <option value="GITLAB_INCOMING_MAIL_TOKEN">Gitlab Incoming Mail Token</option>
                <option value="GITLAB_KUBERNETES_AGENT_TOKEN">Gitlab Kubernetes Agent Token</option>
                <option value="GITLAB_OAUTH_APP_SECRET">Gitlab Oauth App Secret</option>
                <option value="GITLAB_PAT">Gitlab Pat</option>
                <option value="GITLAB_PAT_ROUTABLE">Gitlab Pat Routable</option>
                <option value="GITLAB_PTT">Gitlab Ptt</option>
                <option value="GITLAB_RRT">Gitlab Rrt</option>
                <option value="GITLAB_RUNNER_AUTHENTICATION_TOKEN">Gitlab Runner Authentication Token</option>
                <option value="GITLAB_RUNNER_AUTHENTICATION_TOKEN_ROUTABLE">Gitlab Runner Authentication Token Routable</option>
                <option value="GITLAB_SCIM_TOKEN">Gitlab Scim Token</option>
                <option value="GITLAB_SESSION_COOKIE">Gitlab Session Cookie</option>
                <option value="GITTER_ACCESS_TOKEN">Gitter Access Token</option>
                <option value="GOCARDLESS_API_TOKEN">Gocardless Api Token</option>
                <option value="GRAFANA_API_KEY">Grafana Api Key</option>
                <option value="GRAFANA_CLOUD_API_TOKEN">Grafana Cloud Api Token</option>
                <option value="GRAFANA_SERVICE_ACCOUNT_TOKEN">Grafana Service Account Token</option>
                <option value="GREPTILE_API_KEY">Greptile Api Key</option>
                <option value="GROQ_API_KEY">Groq Api Key</option>
                <option value="HARNESS_API_KEY">Harness Api Key</option>
                <option value="HASHICORP_TF_API_TOKEN">Hashicorp Tf Api Token</option>
                <option value="HASHICORP_TF_PASSWORD">Hashicorp Tf Password</option>
                <option value="HEROKU_API_KEY">Heroku Api Key</option>
                <option value="HUBSPOT_API_KEY">Hubspot Api Key</option>
                <option value="HUGGINGFACE_ACCESS_TOKEN">Huggingface Access Token</option>
                <option value="HUGGINGFACE_ORGANIZATION_API_TOKEN">Huggingface Organization Api Token</option>
                <option value="INFRACOST_API_TOKEN">Infracost Api Token</option>
                <option value="INTERCOM_API_KEY">Intercom Api Key</option>
                <option value="INTRA42_CLIENT_SECRET">Intra42 Client Secret</option>
                <option value="JFROG_API_KEY">Jfrog Api Key</option>
                <option value="JFROG_IDENTITY_TOKEN">Jfrog Identity Token</option>
                <option value="JWT">Jwt</option>
                <option value="KRAKEN_ACCESS_TOKEN">Kraken Access Token</option>
                <option value="KUBERNETES_SECRET_YAML">Kubernetes Secret Yaml</option>
                <option value="KUCOIN_ACCESS_TOKEN">Kucoin Access Token</option>
                <option value="KUCOIN_SECRET_KEY">Kucoin Secret Key</option>
                <option value="LAUNCHDARKLY_ACCESS_TOKEN">Launchdarkly Access Token</option>
                <option value="LINEAR_API_KEY">Linear Api Key</option>
                <option value="LINEAR_CLIENT_SECRET">Linear Client Secret</option>
                <option value="LINKEDIN_CLIENT_ID">Linkedin Client Id</option>
                <option value="LINKEDIN_CLIENT_SECRET">Linkedin Client Secret</option>
                <option value="LOB_API_KEY">Lob Api Key</option>
                <option value="LOB_PUB_API_KEY">Lob Pub Api Key</option>
                <option value="LOOKER_CLIENT_ID">Looker Client Id</option>
                <option value="LOOKER_CLIENT_SECRET">Looker Client Secret</option>
                <option value="MAILCHIMP_API_KEY">Mailchimp Api Key</option>
                <option value="MAILGUN_PRIVATE_API_TOKEN">Mailgun Private Api Token</option>
                <option value="MAILGUN_PUB_KEY">Mailgun Pub Key</option>
                <option value="MAILGUN_SIGNING_KEY">Mailgun Signing Key</option>
                <option value="MAPBOX_API_TOKEN">Mapbox Api Token</option>
                <option value="MATTERMOST_ACCESS_TOKEN">Mattermost Access Token</option>
                <option value="MAXMIND_LICENSE_KEY">Maxmind License Key</option>
                <option value="MESSAGEBIRD_API_TOKEN">Messagebird Api Token</option>
                <option value="MESSAGEBIRD_CLIENT_ID">Messagebird Client Id</option>
                <option value="MICROSOFT_TEAMS_WEBHOOK">Microsoft Teams Webhook</option>
                <option value="MISTRAL_API_KEY">Mistral Api Key</option>
                <option value="NETLIFY_ACCESS_TOKEN">Netlify Access Token</option>
                <option value="NEW_RELIC_BROWSER_API_TOKEN">New Relic Browser Api Token</option>
                <option value="NEW_RELIC_INSERT_KEY">New Relic Insert Key</option>
                <option value="NEW_RELIC_USER_API_ID">New Relic User Api Id</option>
                <option value="NEW_RELIC_USER_API_KEY">New Relic User Api Key</option>
                <option value="NOTION_API_TOKEN">Notion Api Token</option>
                <option value="NPM_ACCESS_TOKEN">Npm Access Token</option>
                <option value="NUGET_CONFIG_PASSWORD">Nuget Config Password</option>
                <option value="NVIDIA_API_KEY">Nvidia Api Key</option>
                <option value="NYTIMES_ACCESS_TOKEN">Nytimes Access Token</option>
                <option value="OCTOPUS_DEPLOY_API_KEY">Octopus Deploy Api Key</option>
                <option value="OKTA_ACCESS_TOKEN">Okta Access Token</option>
                <option value="OLLAMA_API_KEY">Ollama Api Key</option>
                <option value="OPENAI_API_KEY">Openai Api Key</option>
                <option value="OPENROUTER_API_KEY">Openrouter Api Key</option>
                <option value="OPENSHIFT_USER_TOKEN">Openshift User Token</option>
                <option value="PLAID_API_TOKEN">Plaid Api Token</option>
                <option value="PLAID_CLIENT_ID">Plaid Client Id</option>
                <option value="PLAID_SECRET_KEY">Plaid Secret Key</option>
                <option value="PLANETSCALE_API_TOKEN">Planetscale Api Token</option>
                <option value="PLANETSCALE_ID">Planetscale Id</option>
                <option value="PLANETSCALE_OAUTH_TOKEN">Planetscale Oauth Token</option>
                <option value="PLANETSCALE_PASSWORD">Planetscale Password</option>
                <option value="POSTHOG_PERSONAL_API_KEY">Posthog Personal Api Key</option>
                <option value="POSTHOG_PROJECT_API_KEY">Posthog Project Api Key</option>
                <option value="POSTMAN_API_TOKEN">Postman Api Token</option>
                <option value="PREFECT_API_TOKEN">Prefect Api Token</option>
                <option value="PRIVATEAI_API_TOKEN">Privateai Api Token</option>
                <option value="PULUMI_API_TOKEN">Pulumi Api Token</option>
                <option value="PYPI_UPLOAD_TOKEN">Pypi Upload Token</option>
                <option value="RAPIDAPI_ACCESS_TOKEN">Rapidapi Access Token</option>
                <option value="README_API_TOKEN">Readme Api Token</option>
                <option value="REPLICATE_API_TOKEN">Replicate Api Token</option>
                <option value="RUBYGEMS_API_TOKEN">Rubygems Api Token</option>
                <option value="SCALINGO_API_TOKEN">Scalingo Api Token</option>
                <option value="SENDBIRD_ACCESS_ID">Sendbird Access Id</option>
                <option value="SENDBIRD_ACCESS_TOKEN">Sendbird Access Token</option>
                <option value="SENDGRID_API_TOKEN">Sendgrid Api Token</option>
                <option value="SENDINBLUE_API_TOKEN">Sendinblue Api Token</option>
                <option value="SENTRY_ACCESS_TOKEN">Sentry Access Token</option>
                <option value="SENTRY_ORG_TOKEN">Sentry Org Token</option>
                <option value="SENTRY_USER_TOKEN">Sentry User Token</option>
                <option value="SETTLEMINT_APPLICATION_ACCESS_TOKEN">Settlemint Application Access Token</option>
                <option value="SETTLEMINT_PERSONAL_ACCESS_TOKEN">Settlemint Personal Access Token</option>
                <option value="SETTLEMINT_SERVICE_ACCESS_TOKEN">Settlemint Service Access Token</option>
                <option value="SHIPPO_API_TOKEN">Shippo Api Token</option>
                <option value="SHOPIFY_ACCESS_TOKEN">Shopify Access Token</option>
                <option value="SHOPIFY_CUSTOM_ACCESS_TOKEN">Shopify Custom Access Token</option>
                <option value="SHOPIFY_PRIVATE_APP_ACCESS_TOKEN">Shopify Private App Access Token</option>
                <option value="SHOPIFY_SHARED_SECRET">Shopify Shared Secret</option>
                <option value="SIDEKIQ_SECRET">Sidekiq Secret</option>
                <option value="SIDEKIQ_SENSITIVE_URL">Sidekiq Sensitive Url</option>
                <option value="SLACK_APP_TOKEN">Slack App Token</option>
                <option value="SLACK_BOT_TOKEN">Slack Bot Token</option>
                <option value="SLACK_CONFIG_ACCESS_TOKEN">Slack Config Access Token</option>
                <option value="SLACK_CONFIG_REFRESH_TOKEN">Slack Config Refresh Token</option>
                <option value="SLACK_LEGACY_BOT_TOKEN">Slack Legacy Bot Token</option>
                <option value="SLACK_LEGACY_TOKEN">Slack Legacy Token</option>
                <option value="SLACK_LEGACY_WORKSPACE_TOKEN">Slack Legacy Workspace Token</option>
                <option value="SLACK_USER_TOKEN">Slack User Token</option>
                <option value="SLACK_WEBHOOK_URL">Slack Webhook Url</option>
                <option value="SNYK_API_TOKEN">Snyk Api Token</option>
                <option value="SONAR_API_TOKEN">Sonar Api Token</option>
                <option value="SOURCEGRAPH_ACCESS_TOKEN">Sourcegraph Access Token</option>
                <option value="SQUARESPACE_ACCESS_TOKEN">Squarespace Access Token</option>
                <option value="SQUARE_ACCESS_TOKEN">Square Access Token</option>
                <option value="STABILITY_AI_API_KEY">Stability Ai Api Key</option>
                <option value="STRIPE_ACCESS_TOKEN">Stripe Access Token</option>
                <option value="SUMOLOGIC_ACCESS_ID">Sumologic Access Id</option>
                <option value="SUMOLOGIC_ACCESS_TOKEN">Sumologic Access Token</option>
                <option value="TELEGRAM_BOT_API_TOKEN">Telegram Bot Api Token</option>
                <option value="TOGETHERAI_API_KEY">Togetherai Api Key</option>
                <option value="TRAVISCI_ACCESS_TOKEN">Travisci Access Token</option>
                <option value="TWILIO_API_KEY">Twilio Api Key</option>
                <option value="TWITCH_API_TOKEN">Twitch Api Token</option>
                <option value="TWITTER_ACCESS_SECRET">Twitter Access Secret</option>
                <option value="TWITTER_ACCESS_TOKEN">Twitter Access Token</option>
                <option value="TWITTER_API_KEY">Twitter Api Key</option>
                <option value="TWITTER_API_SECRET">Twitter Api Secret</option>
                <option value="TWITTER_BEARER_TOKEN">Twitter Bearer Token</option>
                <option value="TYPEFORM_API_TOKEN">Typeform Api Token</option>
                <option value="VAULT_BATCH_TOKEN">Vault Batch Token</option>
                <option value="VAULT_SERVICE_TOKEN">Vault Service Token</option>
                <option value="VERCEL_AI_GATEWAY_KEY">Vercel Ai Gateway Key</option>
                <option value="VERCEL_API_TOKEN">Vercel Api Token</option>
                <option value="VERCEL_APP_ACCESS_TOKEN">Vercel App Access Token</option>
                <option value="VERCEL_APP_REFRESH_TOKEN">Vercel App Refresh Token</option>
                <option value="VERCEL_INTEGRATION_TOKEN">Vercel Integration Token</option>
                <option value="VERCEL_PERSONAL_ACCESS_TOKEN">Vercel Personal Access Token</option>
                <option value="WEIGHTS_AND_BIASES_API_KEY">Weights And Biases Api Key</option>
                <option value="XAI_API_KEY">Xai Api Key</option>
                <option value="YANDEX_ACCESS_TOKEN">Yandex Access Token</option>
                <option value="YANDEX_API_KEY">Yandex Api Key</option>
                <option value="YANDEX_AWS_ACCESS_TOKEN">Yandex Aws Access Token</option>
                <option value="ZENDESK_SECRET_KEY">Zendesk Secret Key</option>
              </optgroup>
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-2 uppercase tracking-wider font-semibold">Domain</label>
            <select
              className="input"
              value={filters.domain}
              onChange={(e) => { setFilters({ ...filters, domain: e.target.value }); setPage(1); }}
            >
              <option value="">All Domains</option>
              {domainsData?.map((domain) => (
                <option key={domain.id} value={domain.name}>{domain.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-2 uppercase tracking-wider font-semibold">Status</label>
            <select
              className="input"
              value={filters.status}
              onChange={(e) => { setFilters({ ...filters, status: e.target.value }); setPage(1); }}
            >
              <option value="">All</option>
              <option value="unreviewed">🔲 Unreviewed</option>
              <option value="verified">✅ Verified</option>
              <option value="false_positive">❌ False Positive</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-2 uppercase tracking-wider font-semibold">Search</label>
            <div className="flex space-x-2">
              <input
                type="text"
                className="input flex-1"
                placeholder="Search repository, file..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              />
              <button
                onClick={handleSearch}
                className="btn btn-primary flex items-center space-x-1 px-4"
              >
                <Search className="w-4 h-4" />
                <span>Search</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <div className="card">
        {/* Results count & Export buttons */}
        {data && (
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-700">
            <div>
              <span className="text-sm text-gray-400 block sm:inline">
                <span className="text-base font-bold text-white">{data.pagination.total}</span> {data.pagination.total === 1 ? 'result' : 'results'} found
              </span>
              {data.pagination.pages > 1 && (
                <span className="text-xs text-gray-500 sm:ml-4 block sm:inline font-mono">
                  Showing {((page - 1) * 20) + 1}–{Math.min(page * 20, data.pagination.total)} of {data.pagination.total}
                </span>
              )}
            </div>
            {/* Export Actions */}
            <div className="flex items-center space-x-2">
              <button
                onClick={() => exportData('csv')}
                disabled={exporting !== null || data.pagination.total === 0}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-gray-300 transition-colors font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}
              >
                {exporting === 'csv' ? (
                  <span className="w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                CSV
              </button>
              <button
                onClick={() => exportData('json')}
                disabled={exporting !== null || data.pagination.total === 0}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-gray-300 transition-colors font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.15)' }}
              >
                {exporting === 'json' ? (
                  <span className="w-3.5 h-3.5 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                JSON
              </button>
            </div>
          </div>
        )}
        <div className="space-y-4">
          {data?.findings.map((finding) => {
            const crit = finding.criticality?.toUpperCase() || 'INFO';
            const cardStyle = CRITICALITY_CARD_STYLES[crit] || CRITICALITY_CARD_STYLES.INFO;
            const badgeStyle = CRITICALITY_BADGE_STYLES[crit] || CRITICALITY_BADGE_STYLES.INFO;
            return (
              <div
                key={finding.id}
                className="rounded-sm p-4 transition-all"
                style={{ border: '1px solid', ...cardStyle }}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <span className="text-2xl">{getCriticalityIcon(finding.criticality)}</span>
                      <span
                        className="px-3 py-1 rounded-sm text-xs font-bold uppercase tracking-wider"
                        style={{ border: '1px solid', ...badgeStyle }}
                      >
                        {finding.criticality}
                      </span>
                      <span
                        className="px-3 py-1 rounded-sm text-xs uppercase tracking-wider"
                        style={{ border: '1px solid rgba(59,130,246,0.2)', backgroundColor: 'rgba(30,58,138,0.1)', color: '#93C5FD' }}
                      >
                        {finding.primaryType.replace(/_/g, ' ')}
                      </span>
                      {finding.scan?.domain?.name && (
                        <span
                          className="px-3 py-1 rounded-sm text-xs"
                          style={{ border: '1px solid rgba(59,130,246,0.3)', backgroundColor: 'rgba(30,58,138,0.2)', color: '#93c5fd' }}
                        >
                          🌐 {finding.scan.domain.name}
                        </span>
                      )}
                      <span className="text-sm font-bold" style={{ color: '#60A5FA' }}>
                        Score: {finding.score.toFixed(1)}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center space-x-2 text-sm">
                        <a
                          href={finding.repositoryUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300 hover:text-blue-400 flex items-center space-x-1 transition-all"
                          
                        >
                          <span dangerouslySetInnerHTML={{ __html: highlightText(finding.repository, filters.search) }} />
                          <ExternalLink className="w-4 h-4" />
                        </a>
                        <span className="text-gray-500">•</span>
                        {(() => {
                          // Legacy findings used filePath='issue', newer ones use 'issue-12'. Handle both.
                          const isIssue = finding.filePath?.startsWith('issue-') || (finding.filePath === 'issue' && finding.repositoryUrl?.includes('/issues/'));
                          const href = finding.fileUrl || (isIssue ? finding.repositoryUrl : `${finding.repositoryUrl}/blob/HEAD/${finding.filePath}`);

                          let displayFile = finding.filePath;
                          if (isIssue) {
                            if (finding.filePath === 'issue') {
                              const issueNum = finding.repositoryUrl?.split('/').pop() || '';
                              displayFile = `Issue #${issueNum}`;
                            } else {
                              displayFile = `Issue #${finding.filePath.replace('issue-', '')}`;
                            }
                          }

                          const titleText = isIssue ? "View issue on GitHub" : (finding.filePath === finding.commitSha ? "View commit on GitHub" : "View file on GitHub");

                          return (
                            <a
                              href={href}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-gray-400 hover:text-gray-200 hover:text-blue-400 flex items-center gap-1 transition-all"
                              
                              title={titleText}
                            >
                              <span dangerouslySetInnerHTML={{ __html: highlightText(displayFile, filters.search) }} />
                              <ExternalLink className="w-3 h-3 flex-shrink-0" />
                            </a>
                          );
                        })()}
                      </div>

                      {(() => {
                        const allSecrets = [...(finding.secrets || [])].sort((a, b) => {
                          const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
                          return (order[a.criticality] ?? 5) - (order[b.criticality] ?? 5);
                        });
                        const isExpanded = expandedFindings.has(finding.id);
                        const displaySecrets = isExpanded ? allSecrets : allSecrets.slice(0, 1);
                        const hasMore = allSecrets.length > 1;

                        return (
                          <>
                            {displaySecrets.map((secret) => (
                              <div key={secret.id} className="mt-4 p-4 rounded-md transition-all" style={{ border: '1px solid rgba(255,255,255,0.06)', backgroundColor: 'rgba(0,0,0,0.25)' }}>
                                <div className="flex items-center gap-3 mb-2">
                                  <span
                                    className="px-2 py-0.5 rounded-sm text-xs uppercase tracking-wider font-bold"
                                    style={{ ...CRITICALITY_BADGE_STYLES[secret.criticality] }}
                                  >{secret.criticality}</span>
                                  <span className="text-blue-400 font-bold text-xs uppercase">{secret.type.replace(/_/g, ' ')}</span>
                                </div>

                                <div className="mb-3 p-3 rounded-sm font-mono text-sm" style={{ border: '1px solid rgba(139,92,246,0.15)', backgroundColor: 'rgba(0,0,0,0.3)' }}>
                                  <div className="text-xs mb-1 uppercase tracking-wider font-bold" style={{ color: '#A78BFA' }}>🔐 Secret Match:</div>
                                  <div
                                    className="break-all select-all"
                                    style={{ color: '#C4B5FD' }}
                                    dangerouslySetInnerHTML={{ __html: highlightText(secret.content, filters.search) }}
                                  />
                                </div>

                                <div className="p-3 rounded-sm font-mono text-sm max-h-64 overflow-y-auto" style={{ border: '1px solid rgba(6,182,212,0.2)', backgroundColor: 'rgba(0,0,0,0.5)' }}>
                                  <div className="text-xs mb-1 uppercase tracking-wider" style={{ color: 'rgba(156,163,175,0.5)' }}>📄 Context:</div>
                                  <pre
                                    className="text-xs whitespace-pre-wrap break-all"
                                    style={{ color: '#93C5FD' }}
                                    dangerouslySetInnerHTML={{ __html: highlightText(secret.context, filters.search) }}
                                  />
                                </div>
                              </div>
                            ))}

                            {hasMore && (
                              <div className="mt-2 text-center">
                                <button
                                  onClick={() => toggleExpand(finding.id)}
                                  className="mx-auto flex items-center gap-2 px-6 py-2 bg-cyan-900/10 hover:bg-cyan-900/30 border border-gray-700 hover:border-cyan-500/50 rounded-full text-xs text-blue-400 font-bold uppercase tracking-widest transition-all"
                                  
                                >
                                  {isExpanded ? (
                                    <>
                                      Collapse <ChevronUp className="w-4 h-4" />
                                    </>
                                  ) : (
                                    <>
                                      Show {allSecrets.length - 1} more secrets <ChevronDown className="w-4 h-4" />
                                    </>
                                  )}
                                </button>
                              </div>
                            )}
                          </>
                        );
                      })()}

                      <div className="flex items-center gap-4 text-sm flex-wrap mt-4">
                        {finding.fileUrl && (
                          <a
                            href={finding.fileUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 hover:text-blue-400 flex items-center space-x-1 transition-all"
                            
                          >
                            <span>View File</span>
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}
                        {finding.commitUrl && (
                          <a
                            href={finding.commitUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 hover:text-blue-400 flex items-center space-x-1 transition-all"
                            
                          >
                            <span>View Commit</span>
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}
                      </div>

                      <div className="flex items-center gap-4 text-xs flex-wrap" >
                        {finding.commitDate ? (
                          <span className="flex items-center gap-1 text-gray-300" title="Date of the last commit that modified this file on GitHub">
                            <span className="text-gray-500 uppercase tracking-wider" >File modified:</span>
                            <span className="font-bold">📅 {new Date(finding.commitDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-gray-500 italic" title="File modification date not yet available — will be fetched on next scan">
                            <span className="text-gray-600 uppercase tracking-wider" >File modified:</span>
                            <span>N/A</span>
                          </span>
                        )}
                        <span className="flex items-center gap-1 text-gray-500" title="Date when this finding was detected by the scanner">
                          <span className="text-gray-600 uppercase tracking-wider" >Detected:</span>
                          <span>{new Date(finding.createdAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col space-y-2 ml-4">
                    <button
                      onClick={() => handleMarkVerified(finding)}
                      className="px-3 py-2 rounded-sm text-xs uppercase tracking-wider font-bold flex items-center space-x-1 transition-all"
                      style={finding.verified
                        ? { color: '#93C5FD', border: '1px solid rgba(16,185,129,0.35)', background: 'rgba(16,185,129,0.12)' }
                        : { color: '#60A5FA', border: '1px solid rgba(59,130,246,0.2)', backgroundColor: 'rgba(30,58,138,0.1)' }
                      }
                    >
                      <Check className="w-4 h-4" />
                      <span>{finding.verified ? 'Verified' : 'Verify'}</span>
                    </button>

                    <button
                      onClick={() => handleMarkFalsePositive(finding)}
                      className="px-3 py-2 rounded-sm text-xs uppercase tracking-wider font-bold flex items-center space-x-1 transition-all"
                      style={finding.falsePositive
                        ? { color: '#C4B5FD', border: '1px solid rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.12)' }
                        : { color: '#A78BFA', border: '1px solid rgba(239,68,68,0.2)', backgroundColor: 'rgba(127,29,29,0.08)' }
                      }
                    >
                      <X className="w-4 h-4" />
                      <span>{finding.falsePositive ? 'False +' : 'Mark FP'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {data && data.pagination.pages > 1 && (
          <div className="flex items-center justify-center space-x-2 mt-6">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page === 1}
              className="btn btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="text-gray-400">
              Page {page} of {data.pagination.pages}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page === data.pagination.pages}
              className="btn btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        )}
      </div>

    </div>
  );
}
