import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { findingsAPI, scanAPI, domainAPI } from '../lib/api';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { AlertTriangle, TrendingUp, Shield, Clock, AlertCircle, X, Globe, ChevronDown } from 'lucide-react';

const CRITICALITY_COLORS = {
  critical: '#d600ff', // Cyber purple/magenta
  high: '#bd00ff',     // Cyber magenta
  medium: '#00b8ff',   // Cyber blue
  low: '#00ff9f',      // Cyber cyan
  info: '#001eff',     // Cyber electric blue
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [selectedDomain, setSelectedDomain] = useState<string>(''); // '' = all domains
  const [domainDropdownOpen, setDomainDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    if (!domainDropdownOpen) return;
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDomainDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [domainDropdownOpen]);

  const [dismissedErrors, setDismissedErrors] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem('dismissedErrors');
      return new Set(stored ? JSON.parse(stored) : []);
    } catch {
      return new Set();
    }
  });

  // Fetch list of all domains for the selector
  const { data: domainsData } = useQuery({
    queryKey: ['domains-list'],
    queryFn: async () => {
      const response = await domainAPI.getAll();
      return response.data;
    },
  });
  const domains: any[] = Array.isArray(domainsData) ? domainsData : [];
  const selectedDomainObj = domains.find((d: any) => d.name === selectedDomain) || null;

  const { data: stats, isLoading: statsLoading, isFetching: statsFetching } = useQuery({
    queryKey: ['stats', selectedDomain],
    queryFn: async () => {
      const params: any = {};
      if (selectedDomain) params.domain = selectedDomain;
      const response = await findingsAPI.getStats(params);
      return response.data;
    },
  });

  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans', { limit: 10, domainId: selectedDomainObj?.id || '' }],
    queryFn: async () => {
      const params: any = { limit: 10, page: 1 };
      if (selectedDomainObj?.id) params.domainId = selectedDomainObj.id;
      const response = await scanAPI.getAll(params);
      return response.data;
    },
    refetchInterval: (query) => {
      const data = query.state.data as any;
      const hasRunning = data?.scans?.some((s: any) => s.status === 'RUNNING' || s.status === 'QUEUED');
      return hasRunning ? 10000 : false;
    },
  });

  // Fetch top emails filtered by domain
  const { data: emailFindings } = useQuery({
    queryKey: ['emails', selectedDomain],
    queryFn: async () => {
      const params: any = { type: 'EMAIL', limit: 10000 };
      if (selectedDomain) params.domain = selectedDomain;
      const response = await findingsAPI.getAll(params);
      return response.data;
    },
  });

  // Fetch critical + high findings filtered by domain
  const { data: criticalFindings } = useQuery({
    queryKey: ['critical-high-findings', selectedDomain],
    queryFn: async () => {
      const domainParam = selectedDomain ? { domain: selectedDomain } : {};
      const [critRes, highRes] = await Promise.all([
        findingsAPI.getAll({ criticality: 'CRITICAL', limit: 10, ...domainParam }),
        findingsAPI.getAll({ criticality: 'HIGH', limit: 10, ...domainParam }),
      ]);
      const combined = [
        ...(critRes.data.findings || []),
        ...(highRes.data.findings || []),
      ].sort((a: any, b: any) => b.score - a.score).slice(0, 10);
      return { findings: combined };
    },
  });

  const failedScans = scansData?.scans?.filter((scan: any) => scan.status === 'FAILED' && !dismissedErrors.has(scan.id)) || [];

  const dismissError = (scanId: string) => {
    setDismissedErrors(prev => {
      const updated = new Set(prev).add(scanId);
      localStorage.setItem('dismissedErrors', JSON.stringify(Array.from(updated)));
      return updated;
    });
  };

  // Only show full-page loader on the very first load (no data yet)
  // On domain switch, keep showing existing data with a subtle refresh indicator
  if ((statsLoading && !stats) || (scansLoading && !scansData)) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-xl neon-text cyber-pulse">LOADING DASHBOARD...</div>
      </div>
    );
  }

  const overview = stats?.overview;
  const criticalityDataAll = overview?.byCriticality
    ? [
      { name: 'Critical', key: 'CRITICAL', value: overview.byCriticality?.critical || 0, color: CRITICALITY_COLORS.critical },
      { name: 'High', key: 'HIGH', value: overview.byCriticality?.high || 0, color: CRITICALITY_COLORS.high },
      { name: 'Medium', key: 'MEDIUM', value: overview.byCriticality?.medium || 0, color: CRITICALITY_COLORS.medium },
      { name: 'Low', key: 'LOW', value: overview.byCriticality?.low || 0, color: CRITICALITY_COLORS.low },
      { name: 'Info', key: 'INFO', value: overview.byCriticality?.info || 0, color: CRITICALITY_COLORS.info },
    ]
    : [];

  const criticalityTotal = criticalityDataAll.reduce((sum, d) => sum + d.value, 0);

  const topRepos = stats?.topRepositories?.slice(0, 10) || [];
  const topFiles = stats?.topFiles?.slice(0, 10) || [];
  const topTypes = stats?.byType
    ? [...stats.byType].sort((a: any, b: any) => b.count - a.count).slice(0, 10)
    : [];

  // Extract and rank emails by frequency
  const emailRanking = emailFindings?.findings?.reduce((acc: any, finding: any) => {
    for (const secret of finding.secrets || []) {
      if (secret.type !== 'EMAIL') continue;

      // Use content if it's not a hash (no hashes contain @), otherwise use contentPreview as-is
      let email = secret.content || '';
      if (!email.includes('@')) {
        email = secret.contentPreview || '';
      }
      if (!email) continue;

      if (!acc[email]) {
        acc[email] = { email, count: 0, repositories: new Set() };
      }
      acc[email].count++;
      acc[email].repositories.add(finding.repository);
    }
    return acc;
  }, {});

  // Unique email count comes from the backend stats (accurate, domain-filtered)
  const totalUniqueEmails = stats?.uniqueEmails ?? 0;

  const topEmails = emailRanking
    ? Object.values(emailRanking).map((item: any) => ({
      email: item.email,
      count: item.count,
      repos: item.repositories.size
    })).sort((a: any, b: any) => b.count - a.count).slice(0, 10)
    : [];

  return (
    <div className="space-y-8">
      {/* Header + Domain Filter */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-4xl font-bold mb-2 neon-text uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>
            Dashboard
          </h2>
          <p className="text-cyan-400 flex items-center gap-2" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
            {selectedDomain
              ? <>Showing findings for <span className="text-cyan-300 font-bold">{selectedDomain}</span></>
              : 'Overview of your security findings across all domains'}
            {statsFetching && (
              <span className="inline-block w-3 h-3 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
            )}
          </p>
        </div>

        {/* Domain Filter Dropdown */}
        <div className="relative" style={{ minWidth: '220px' }} ref={dropdownRef}>
          <button
            onClick={() => setDomainDropdownOpen(o => !o)}
            className="w-full flex items-center justify-between gap-2 px-4 py-2.5 bg-black/60 border rounded-sm transition-all text-left"
            style={{
              borderColor: selectedDomain ? 'rgba(0,255,159,0.6)' : 'rgba(0,184,255,0.35)',
              boxShadow: selectedDomain ? '0 0 12px rgba(0,255,159,0.2)' : 'none',
            }}
          >
            <div className="flex items-center gap-2 min-w-0">
              <Globe className="w-4 h-4 flex-shrink-0" style={{ color: selectedDomain ? '#00ff9f' : '#00b8ff' }} />
              <span className="truncate text-sm font-bold uppercase tracking-wider"
                style={{ fontFamily: 'Rajdhani, sans-serif', color: selectedDomain ? '#00ff9f' : '#00b8ff' }}>
                {selectedDomain || 'All Domains'}
              </span>
            </div>
            <ChevronDown
              className="w-4 h-4 flex-shrink-0 transition-transform"
              style={{ color: selectedDomain ? '#00ff9f' : '#00b8ff', transform: domainDropdownOpen ? 'rotate(180deg)' : 'none' }}
            />
          </button>

          {domainDropdownOpen && (
            <div
              className="absolute right-0 mt-1 w-full z-50 rounded-sm border overflow-hidden"
              style={{ backgroundColor: '#080c10', borderColor: 'rgba(0,184,255,0.4)', boxShadow: '0 0 24px rgba(0,184,255,0.2)' }}
            >
              {/* All Domains option */}
              <button
                onClick={() => { setSelectedDomain(''); setDomainDropdownOpen(false); }}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-cyan-500/10"
                style={{ borderBottom: '1px solid rgba(0,184,255,0.15)' }}
              >
                <Globe className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-sm font-bold uppercase tracking-wider text-cyan-300" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                  All Domains
                </span>
                {!selectedDomain && <span className="ml-auto text-cyan-400 text-xs">✓</span>}
              </button>

              {/* Individual domains */}
              {domains.map((d: any) => (
                <button
                  key={d.id}
                  onClick={() => { setSelectedDomain(d.name); setDomainDropdownOpen(false); }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-cyan-500/10"
                  style={{ borderBottom: '1px solid rgba(0,184,255,0.1)' }}
                >
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: d.active ? '#00ff9f' : '#555' }}
                  />
                  <span className="text-sm truncate text-cyan-200" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                    {d.name}
                  </span>
                  {selectedDomain === d.name && <span className="ml-auto text-cyan-400 text-xs">✓</span>}
                </button>
              ))}

              {domains.length === 0 && (
                <div className="px-4 py-3 text-cyan-500/50 text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                  No domains configured
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Active domain filter banner */}
      {selectedDomain && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-sm border"
          style={{ backgroundColor: 'rgba(0,255,159,0.05)', borderColor: 'rgba(0,255,159,0.3)', boxShadow: '0 0 16px rgba(0,255,159,0.08)' }}>
          <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span className="text-sm text-cyan-300 flex-1" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
            Filtering all stats for domain: <strong className="text-cyan-100">{selectedDomain}</strong>
          </span>
          <button
            onClick={() => setSelectedDomain('')}
            className="flex items-center gap-1 text-xs text-cyan-500 hover:text-cyan-300 transition-colors uppercase tracking-wider"
            style={{ fontFamily: 'Rajdhani, sans-serif' }}
          >
            <X className="w-3.5 h-3.5" /> Clear filter
          </button>
        </div>
      )}


      {/* Error Alerts */}
      {failedScans.length > 0 && (
        <div className="space-y-3">
          {failedScans.map(scan => (
            <div key={scan.id} className="card neon-box-purple bg-purple-900/10 border-2 border-purple-500/50">
              <div className="flex items-start space-x-3">
                <AlertCircle className="w-6 h-6 text-purple-400 flex-shrink-0 mt-1" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-purple))' }} />
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-purple-300 mb-1 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>
                    Scan Failed: {scan.domain?.name}
                  </h3>
                  <p className="text-purple-200 text-sm" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                    {scan.errorMessage || 'Unknown error occurred during scan'}
                  </p>
                  <p className="text-purple-400/60 text-xs mt-2" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                    {new Date(scan.createdAt).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => dismissError(scan.id)}
                  className="text-purple-400 hover:text-purple-300 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <button
          onClick={() => navigate(`/findings${selectedDomain ? `?domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card neon-box hover:scale-105 transition-transform w-full text-left"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-cyan-400 text-sm uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Total Findings</p>
              <p className="text-4xl font-bold mt-1 text-cyan-300" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 10px var(--cyber-cyan)' }}>{overview?.total || 0}</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-cyan-400 cyber-pulse flex-shrink-0" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-cyan))' }} />
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?criticality=CRITICAL${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card neon-box-purple hover:scale-105 transition-transform w-full text-left"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-purple-400 text-sm uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Critical Issues</p>
              <p className="text-4xl font-bold mt-1 text-purple-300" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 10px var(--cyber-purple)' }}>
                {overview?.byCriticality.critical || 0}
              </p>
            </div>
            <Shield className="w-12 h-12 text-purple-400 cyber-pulse flex-shrink-0" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-purple))' }} />
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?status=verified${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card neon-box hover:scale-105 transition-transform w-full text-left"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-cyan-400 text-sm uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Verified</p>
              <p className="text-4xl font-bold mt-1 text-cyan-300" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 10px var(--cyber-cyan)' }}>
                {overview?.verified || 0}
              </p>
            </div>
            <TrendingUp className="w-12 h-12 text-cyan-400 cyber-pulse flex-shrink-0" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-cyan))' }} />
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?status=false_positive${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card neon-box-blue hover:scale-105 transition-transform w-full text-left"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-400 text-sm uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>False Positives</p>
              <p className="text-4xl font-bold mt-1 text-blue-300" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 10px var(--cyber-blue)' }}>
                {overview?.falsePositives || 0}
              </p>
            </div>
            <Clock className="w-12 h-12 text-blue-400 cyber-pulse flex-shrink-0" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-blue))' }} />
          </div>
        </button>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Criticality Distribution — clickable boxes */}
        <div className="card neon-box">
          <h3 className="text-xl font-bold mb-6 text-cyan-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Findings by Criticality</h3>
          <div className="grid grid-cols-5 gap-3 h-full">
            {criticalityDataAll.map((entry) => {
              const pct = criticalityTotal > 0 ? ((entry.value / criticalityTotal) * 100).toFixed(0) : '0';
              const isClickable = entry.value > 0;
              return (
                <button
                  key={entry.key}
                  onClick={() => navigate(`/findings?criticality=${entry.key}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                  disabled={!isClickable}
                  title={isClickable ? `View ${entry.name} findings` : `No ${entry.name} findings`}
                  className="flex flex-col items-center justify-center p-4 rounded-sm border transition-all duration-200 group"
                  style={{
                    borderColor: isClickable ? `${entry.color}50` : '#ffffff15',
                    backgroundColor: isClickable ? `${entry.color}10` : 'rgba(0,0,0,0.2)',
                    cursor: isClickable ? 'pointer' : 'default',
                    opacity: isClickable ? 1 : 0.45,
                  }}
                  onMouseEnter={e => {
                    if (isClickable) {
                      (e.currentTarget as HTMLElement).style.borderColor = entry.color;
                      (e.currentTarget as HTMLElement).style.backgroundColor = `${entry.color}20`;
                      (e.currentTarget as HTMLElement).style.boxShadow = `0 0 16px ${entry.color}40`;
                    }
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLElement).style.borderColor = isClickable ? `${entry.color}50` : '#ffffff15';
                    (e.currentTarget as HTMLElement).style.backgroundColor = isClickable ? `${entry.color}10` : 'rgba(0,0,0,0.2)';
                    (e.currentTarget as HTMLElement).style.boxShadow = 'none';
                  }}
                >
                  <div className="w-3 h-3 rounded-full mb-3 transition-transform group-hover:scale-125"
                    style={{ backgroundColor: entry.color, boxShadow: isClickable ? `0 0 10px ${entry.color}` : 'none' }}
                  />
                  <span className="text-xs uppercase font-bold tracking-widest mb-3" style={{ color: entry.color, fontFamily: 'Rajdhani, sans-serif' }}>
                    {entry.name}
                  </span>
                  <span className="text-4xl font-bold leading-none mb-2"
                    style={{ color: entry.color, fontFamily: 'Orbitron, monospace', textShadow: isClickable ? `0 0 12px ${entry.color}` : 'none' }}>
                    {entry.value}
                  </span>
                  <span className="text-xs opacity-60" style={{ color: entry.color, fontFamily: 'Share Tech Mono, monospace' }}>
                    {pct}%
                  </span>
                  {isClickable && (
                    <span className="mt-3 text-xs opacity-0 group-hover:opacity-70 transition-opacity uppercase tracking-wider"
                      style={{ color: entry.color, fontFamily: 'Rajdhani, sans-serif' }}>
                      View →
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Top 10 Type Count */}
        <div className="card neon-box">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-cyan-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>🏷️ Top 10 Finding Types</h3>
            {stats?.uniqueFindingTypes > 0 && (
              <span className="flex items-center gap-1.5 px-3 py-1 bg-cyan-900/30 border border-cyan-500/40 rounded-sm">
                <span className="text-lg font-bold text-cyan-200" style={{ fontFamily: 'Orbitron, monospace' }}>{stats.uniqueFindingTypes}</span>
                <span className="text-xs text-cyan-400 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>unique</span>
              </span>
            )}
          </div>
          {topTypes.length > 0 ? (
            <div className="space-y-2">
              {topTypes.map((item: any, index: number) => {
                const maxCount = topTypes[0]?.count || 1;
                const pct = Math.round((item.count / maxCount) * 100);
                return (
                  <button
                    key={item.type}
                    onClick={() => navigate(`/findings?type=${encodeURIComponent(item.type)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                    title={`View ${item.type.replace(/_/g, ' ')} findings`}
                    className="w-full flex items-center gap-3 p-2.5 bg-cyan-900/10 border border-cyan-500/20 rounded-sm hover:border-cyan-400 hover:bg-cyan-900/20 hover:shadow-[0_0_12px_rgba(0,255,159,0.2)] transition-all text-left group"
                  >
                    <span className="text-cyan-500/60 font-bold text-sm w-5 text-right flex-shrink-0" style={{ fontFamily: 'Orbitron, monospace' }}>#{index + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-cyan-200 text-xs uppercase tracking-wider truncate" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                          {item.type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-cyan-300 font-bold text-sm ml-2 flex-shrink-0" style={{ fontFamily: 'Orbitron, monospace' }}>
                          {item.count}
                        </span>
                      </div>
                      <div className="w-full bg-cyan-900/20 rounded-full h-1">
                        <div
                          className="h-1 rounded-full transition-all"
                          style={{ width: `${pct}%`, background: 'linear-gradient(90deg, #00ff9f, #00b8ff)' }}
                        />
                      </div>
                    </div>
                    <span className="text-cyan-400 opacity-0 group-hover:opacity-70 transition-opacity text-xs flex-shrink-0" style={{ fontFamily: 'Rajdhani, sans-serif' }}>→</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-cyan-400 neon-text">
              NO DATA AVAILABLE
            </div>
          )}
        </div>
      </div>

      {/* Top Emails and Critical Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Extracted Emails */}
        <div className="card neon-box-purple">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-purple-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>📧 Top Extracted Emails</h3>
            {totalUniqueEmails > 0 && (
              <span className="flex items-center gap-1.5 px-3 py-1 bg-purple-900/30 border border-purple-500/40 rounded-sm">
                <span className="text-lg font-bold text-purple-200" style={{ fontFamily: 'Orbitron, monospace' }}>{totalUniqueEmails}</span>
                <span className="text-xs text-purple-400 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>unique</span>
              </span>
            )}
          </div>
          {topEmails.length > 0 ? (
            <div className="space-y-2">
              {topEmails.map((item: any, index: number) => (
                <button
                  key={item.email}
                  onClick={() => navigate(`/findings?search=${encodeURIComponent(item.email)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                  title={`View findings for ${item.email}`}
                  className="w-full flex items-center justify-between p-3 bg-purple-900/10 border border-purple-500/30 rounded-sm hover:border-purple-400 hover:bg-purple-900/20 hover:shadow-[0_0_12px_rgba(189,0,255,0.25)] transition-all text-left group"
                >
                  <div className="flex items-center space-x-3 flex-1 min-w-0">
                    <span className="text-purple-400 font-bold text-lg" style={{ fontFamily: 'Orbitron, monospace' }}>#{index + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-cyan-300 font-mono text-sm truncate" style={{ fontFamily: 'Share Tech Mono, monospace' }}>{item.email}</div>
                      <div className="text-purple-400/60 text-xs mt-1" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                        Found in {item.repos} repositories
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="bg-purple-500/20 px-3 py-1 rounded-sm border border-purple-500/50">
                      <span className="text-purple-300 font-bold" style={{ fontFamily: 'Orbitron, monospace' }}>{item.count}</span>
                    </div>
                    <span className="text-purple-400 opacity-0 group-hover:opacity-70 transition-opacity text-xs" style={{ fontFamily: 'Rajdhani, sans-serif' }}>View →</span>
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-purple-400">
              NO EMAILS FOUND
            </div>
          )}
        </div>

        {/* Top Critical + High Findings */}
        <div className="card neon-box-purple">
          <h3 className="text-xl font-bold mb-4 text-purple-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>
            🔴 Top Critical &amp; High Findings
          </h3>
          {criticalFindings?.findings && criticalFindings.findings.length > 0 ? (
            <div className="space-y-3">
              {(() => {
                // Group by repository + filePath to avoid showing the exact same file twice
                const seenFiles = new Set<string>();
                const uniqueFiles = criticalFindings.findings.filter((finding: any) => {
                  const key = `${finding.repository}::${finding.filePath}`;
                  if (seenFiles.has(key)) return false;
                  seenFiles.add(key);
                  return true;
                });

                return uniqueFiles.map((finding: any, index: number) => {
                  const isCritical = finding.criticality === 'CRITICAL';
                  return (
                    <button
                      key={finding.id}
                      onClick={() => navigate(`/findings?repository=${encodeURIComponent(finding.repository)}&criticality=${finding.criticality}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                      title={`View ${finding.criticality.toLowerCase()} findings in ${finding.repository}`}
                      className="w-full p-3 bg-purple-900/10 border border-purple-500/30 rounded-sm hover:border-purple-400 hover:bg-purple-900/20 hover:shadow-[0_0_12px_rgba(189,0,255,0.25)] transition-all text-left group"
                    >
                      <div className="flex items-start space-x-2 mb-2">
                        <span className="text-purple-400 font-bold" style={{ fontFamily: 'Orbitron, monospace' }}>#{index + 1}</span>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            {/* Criticality badge */}
                            <span
                              className={`px-2 py-0.5 rounded-sm text-xs uppercase font-bold border ${isCritical
                                ? 'bg-red-500/20 border-red-500/60 text-red-300'
                                : 'bg-orange-500/20 border-orange-500/60 text-orange-300'
                                }`}
                              style={{ fontFamily: 'Rajdhani, sans-serif' }}
                            >
                              {isCritical ? '🔴 CRITICAL' : '🟠 HIGH'}
                            </span>
                            {/* Finding type */}
                            <span className="px-2 py-0.5 bg-purple-500/30 border border-purple-500/50 rounded-sm text-xs uppercase font-bold text-purple-300" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                              {finding.primaryType ? finding.primaryType.replace(/_/g, ' ') : 'UNKNOWN'}
                            </span>
                            <span className="text-cyan-400 text-xs font-bold" style={{ fontFamily: 'Orbitron, monospace' }}>
                              {finding.score.toFixed(1)}
                            </span>
                            <span className="ml-auto text-purple-400 opacity-0 group-hover:opacity-70 transition-opacity text-xs" style={{ fontFamily: 'Rajdhani, sans-serif' }}>View →</span>
                          </div>
                          <div className="text-cyan-300 font-mono text-xs mb-1" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                            {finding.repository} - {finding.filePath === finding.commitSha ? 'commit metadata' : finding.filePath}
                          </div>
                          <div className="bg-black/50 p-2 rounded-sm border border-purple-500/20">
                            <div className="text-purple-300 font-mono text-xs truncate" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                              {finding.secrets?.[0]?.content?.substring(0, 60) || 'Multiple secrets found'}...
                            </div>
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                });
              })()}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-purple-400">
              NO CRITICAL OR HIGH FINDINGS
            </div>
          )}
        </div>
      </div>

      {/* Top Repositories and Top Files */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Repositories */}
        <div className="card neon-box">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-cyan-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Top Repositories</h3>
            {stats?.uniqueRepositories > 0 && (
              <span className="flex items-center gap-1.5 px-3 py-1 bg-cyan-900/30 border border-cyan-500/40 rounded-sm">
                <span className="text-lg font-bold text-cyan-200" style={{ fontFamily: 'Orbitron, monospace' }}>{stats.uniqueRepositories}</span>
                <span className="text-xs text-cyan-400 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>unique</span>
              </span>
            )}
          </div>
          {topRepos.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topRepos} layout="vertical" margin={{ left: 20 }}>
                <XAxis
                  type="number"
                  stroke="#00ff9f"
                  tick={{ fill: '#00ff9f', fontFamily: 'Share Tech Mono, monospace', fontSize: 12 }}
                  axisLine={{ stroke: '#00ff9f', strokeWidth: 2 }}
                />
                <YAxis
                  dataKey="repository"
                  type="category"
                  width={150}
                  stroke="#00ff9f"
                  tick={{ fill: '#00ff9f', fontFamily: 'Share Tech Mono, monospace', fontSize: 11 }}
                  axisLine={{ stroke: '#00ff9f', strokeWidth: 2 }}
                  style={{ cursor: 'pointer' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0a0a0a',
                    border: '2px solid #00b8ff',
                    borderRadius: '4px',
                    fontFamily: 'Share Tech Mono, monospace',
                    color: '#00b8ff',
                    boxShadow: '0 0 20px rgba(0,184,255,0.3)'
                  }}
                  cursor={{ fill: 'rgba(0, 255, 159, 0.1)' }}
                />
                <Bar
                  dataKey="count"
                  fill="url(#colorGradientRepos)"
                  radius={[0, 4, 4, 0]}
                  style={{ filter: 'drop-shadow(0 0 8px #00ff9f)', cursor: 'pointer' }}
                  onClick={(data: any) => navigate(`/findings?repository=${encodeURIComponent(data.repository)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                />
                <defs>
                  <linearGradient id="colorGradientRepos" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#00ff9f" stopOpacity={0.8} />
                    <stop offset="50%" stopColor="#00b8ff" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#bd00ff" stopOpacity={1} />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-32 text-cyan-400 neon-text">
              NO DATA AVAILABLE
            </div>
          )}
        </div>

        {/* Top Files */}
        <div className="card neon-box">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-cyan-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Top Files</h3>
            {stats?.uniqueFiles > 0 && (
              <span className="flex items-center gap-1.5 px-3 py-1 bg-cyan-900/30 border border-cyan-500/40 rounded-sm">
                <span className="text-lg font-bold text-cyan-200" style={{ fontFamily: 'Orbitron, monospace' }}>{stats.uniqueFiles}</span>
                <span className="text-xs text-cyan-400 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>unique</span>
              </span>
            )}
          </div>
          {topFiles.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topFiles} layout="vertical" margin={{ left: 20 }}>
                <XAxis
                  type="number"
                  stroke="#00ff9f"
                  tick={{ fill: '#00ff9f', fontFamily: 'Share Tech Mono, monospace', fontSize: 12 }}
                  axisLine={{ stroke: '#00ff9f', strokeWidth: 2 }}
                />
                <YAxis
                  dataKey="filePath"
                  type="category"
                  width={150}
                  stroke="#00ff9f"
                  tick={{ fill: '#00ff9f', fontFamily: 'Share Tech Mono, monospace', fontSize: 11 }}
                  axisLine={{ stroke: '#00ff9f', strokeWidth: 2 }}
                  style={{ cursor: 'pointer' }}
                  tickFormatter={(val: string) => val.split('/').pop() || val}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0a0a0a',
                    border: '2px solid #00b8ff',
                    borderRadius: '4px',
                    fontFamily: 'Share Tech Mono, monospace',
                    color: '#00b8ff',
                    boxShadow: '0 0 20px rgba(0,184,255,0.3)'
                  }}
                  cursor={{ fill: 'rgba(0, 255, 159, 0.1)' }}
                  formatter={(value: any) => [value, 'Count']}
                  labelFormatter={(label: any) => `File: ${label}`}
                />
                <Bar
                  dataKey="count"
                  fill="url(#colorGradientFiles)"
                  radius={[0, 4, 4, 0]}
                  style={{ filter: 'drop-shadow(0 0 8px #00ff9f)', cursor: 'pointer' }}
                  onClick={(data: any) => navigate(`/findings?search=${encodeURIComponent(data.filePath)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                />
                <defs>
                  <linearGradient id="colorGradientFiles" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#00ff9f" stopOpacity={0.8} />
                    <stop offset="50%" stopColor="#00b8ff" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#bd00ff" stopOpacity={1} />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-32 text-cyan-400 neon-text">
              NO DATA AVAILABLE
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card neon-box">
        <h3 className="text-xl font-bold mb-4 text-cyan-300 uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Recent Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left border-b border-cyan-500/30 cyber-border-top">
                <th className="pb-3 text-cyan-400 uppercase tracking-wider text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Domain</th>
                <th className="pb-3 text-cyan-400 uppercase tracking-wider text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Status</th>
                <th className="pb-3 text-cyan-400 uppercase tracking-wider text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Findings</th>
                <th className="pb-3 text-cyan-400 uppercase tracking-wider text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Critical</th>
                <th className="pb-3 text-cyan-400 uppercase tracking-wider text-sm" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {scansData?.scans?.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => scan.status === 'COMPLETED' && navigate(`/findings?scanId=${scan.id}`)}
                  title={scan.status === 'COMPLETED' ? `View findings for this scan` : undefined}
                  className={`border-b border-cyan-500/20 transition-colors ${scan.status === 'COMPLETED'
                    ? 'hover:bg-cyan-900/10 cursor-pointer hover:shadow-[inset_0_0_20px_rgba(0,255,159,0.05)]'
                    : ''
                    }`}
                >
                  <td className="py-3 text-cyan-300 font-medium" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                    {scan.domain?.name}
                    {scan.status === 'COMPLETED' && (
                      <span className="ml-2 text-cyan-500/40 text-xs opacity-0 group-hover:opacity-100 transition-opacity" style={{ fontFamily: 'Rajdhani, sans-serif' }}>→</span>
                    )}
                  </td>
                  <td className="py-3">
                    <span
                      className={`px-3 py-1 rounded-sm text-xs uppercase tracking-wider font-bold ${scan.status === 'COMPLETED'
                        ? 'bg-gradient-to-r from-cyan-500/20 to-green-500/20 text-cyan-300 border border-cyan-500/50'
                        : scan.status === 'RUNNING'
                          ? 'bg-gradient-to-r from-blue-500/20 to-cyan-500/20 text-blue-300 border border-blue-500/50 cyber-pulse'
                          : scan.status === 'FAILED'
                            ? 'bg-gradient-to-r from-purple-500/20 to-magenta-500/20 text-purple-300 border border-purple-500/50'
                            : 'bg-gray-700/20 text-gray-300 border border-gray-500/30'
                        }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-3 text-cyan-300 font-bold" style={{ fontFamily: 'Orbitron, monospace' }}>{scan.totalFindings}</td>
                  <td className="py-3">
                    <span className="text-purple-400 font-bold text-lg" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 8px var(--cyber-purple)' }}>{scan.criticalCount}</span>
                  </td>
                  <td className="py-3 text-cyan-400/70" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                    {new Date(scan.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
