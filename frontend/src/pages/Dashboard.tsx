import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { findingsAPI, scanAPI, domainAPI } from '../lib/api';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { AlertTriangle, TrendingUp, Shield, Clock, AlertCircle, X, Globe, ChevronDown } from 'lucide-react';
import { getMacroCategory } from '../utils/macroCategories';

const CRITICALITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#3B82F6',
  info: '#6B7280',
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
        <div className="text-lg text-gray-400 animate-subtle-pulse">Loading dashboard...</div>
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
  const topTypes = (() => {
    if (!stats?.byType) return [];
    const macroMap: Record<string, { id: string; name: string; icon: string; color: string; count: number; subTypes: string[] }> = {};
    for (const item of stats.byType) {
      const category = getMacroCategory(item.type);
      if (!macroMap[category.id]) {
        macroMap[category.id] = {
          id: category.id,
          name: category.name,
          icon: category.icon,
          color: category.color,
          count: 0,
          subTypes: []
        };
      }
      macroMap[category.id].count += item.count;
      macroMap[category.id].subTypes.push(item.type);
    }
    return Object.values(macroMap).sort((a, b) => b.count - a.count);
  })();

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
          <h2 className="text-3xl font-bold mb-1 page-title">
            Dashboard
          </h2>
          <p className="text-gray-400 flex items-center gap-2 text-sm">
            {selectedDomain
              ? <>Showing findings for <span className="text-blue-400 font-semibold">{selectedDomain}</span></>
              : 'Overview of your security findings across all domains'}
            {statsFetching && (
              <span className="inline-block w-3 h-3 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
            )}
          </p>
        </div>

        {/* Domain Filter Dropdown */}
        <div className="relative" style={{ minWidth: '220px' }} ref={dropdownRef}>
          <button
            onClick={() => setDomainDropdownOpen(o => !o)}
            className="w-full flex items-center justify-between gap-2 px-4 py-2.5 rounded-lg transition-all text-left"
            style={{
              background: 'rgba(17, 24, 39, 0.8)',
              borderWidth: '1px',
              borderStyle: 'solid',
              borderColor: selectedDomain ? 'rgba(59,130,246,0.4)' : 'rgba(255,255,255,0.1)',
            }}
          >
            <div className="flex items-center gap-2 min-w-0">
              <Globe className="w-4 h-4 flex-shrink-0 text-blue-400" />
              <span className="truncate text-sm font-semibold" style={{ color: selectedDomain ? '#60A5FA' : '#9CA3AF' }}>
                {selectedDomain || 'All Domains'}
              </span>
            </div>
            <ChevronDown
              className="w-4 h-4 flex-shrink-0 transition-transform text-gray-400"
              style={{ transform: domainDropdownOpen ? 'rotate(180deg)' : 'none' }}
            />
          </button>

          {domainDropdownOpen && (
            <div
              className="absolute right-0 mt-1 w-full z-50 rounded-lg border overflow-hidden"
              style={{ backgroundColor: '#111827', borderColor: 'rgba(255,255,255,0.1)', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}
            >
              {/* All Domains option */}
              <button
                onClick={() => { setSelectedDomain(''); setDomainDropdownOpen(false); }}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-white/5"
                style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
              >
                <Globe className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-sm font-medium text-gray-300">
                  All Domains
                </span>
                {!selectedDomain && <span className="ml-auto text-blue-400 text-xs">✓</span>}
              </button>

              {/* Individual domains */}
              {domains.map((d: any) => (
                <button
                  key={d.id}
                  onClick={() => { setSelectedDomain(d.name); setDomainDropdownOpen(false); }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-white/5"
                  style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                >
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: d.active ? '#10B981' : '#4B5563' }}
                  />
                  <span className="text-sm truncate text-gray-300 font-mono">
                    {d.name}
                  </span>
                  {selectedDomain === d.name && <span className="ml-auto text-blue-400 text-xs">✓</span>}
                </button>
              ))}

              {domains.length === 0 && (
                <div className="px-4 py-3 text-gray-500 text-sm">
                  No domains configured
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Active domain filter banner */}
      {selectedDomain && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg border"
          style={{ backgroundColor: 'rgba(59,130,246,0.06)', borderColor: 'rgba(59,130,246,0.2)' }}>
          <Globe className="w-4 h-4 text-blue-400 flex-shrink-0" />
          <span className="text-sm text-gray-300 flex-1">
            Filtering all stats for domain: <strong className="text-blue-400">{selectedDomain}</strong>
          </span>
          <button
            onClick={() => setSelectedDomain('')}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors font-medium"
          >
            <X className="w-3.5 h-3.5" /> Clear filter
          </button>
        </div>
      )}


      {/* Error Alerts */}
      {failedScans.length > 0 && (
        <div className="space-y-3">
          {failedScans.map(scan => (
            <div key={scan.id} className="card" style={{ borderColor: 'rgba(239,68,68,0.25)' }}>
              <div className="flex items-start space-x-3">
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h3 className="text-base font-semibold text-red-300 mb-1">
                    Scan Failed: {scan.domain?.name}
                  </h3>
                  <p className="text-gray-400 text-sm font-mono">
                    {scan.errorMessage || 'Unknown error occurred during scan'}
                  </p>
                  <p className="text-gray-500 text-xs mt-2">
                    {new Date(scan.createdAt).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => dismissError(scan.id)}
                  className="text-gray-500 hover:text-gray-300 transition-colors"
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
          className="card hover:scale-[1.02] transition-all w-full text-left group"
          style={{ borderColor: 'rgba(59,130,246,0.15)' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider mb-1">Total Findings</p>
              <p className="text-3xl font-bold text-white">{overview?.total || 0}</p>
            </div>
            <div className="w-11 h-11 rounded-lg flex items-center justify-center" style={{ background: 'rgba(59,130,246,0.1)' }}>
              <AlertTriangle className="w-5 h-5 text-blue-400" />
            </div>
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?criticality=CRITICAL${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card hover:scale-[1.02] transition-all w-full text-left group"
          style={{ borderColor: 'rgba(239,68,68,0.15)' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider mb-1">Critical Issues</p>
              <p className="text-3xl font-bold text-red-400">
                {overview?.byCriticality.critical || 0}
              </p>
            </div>
            <div className="w-11 h-11 rounded-lg flex items-center justify-center" style={{ background: 'rgba(239,68,68,0.1)' }}>
              <Shield className="w-5 h-5 text-red-400" />
            </div>
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?status=verified${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card hover:scale-[1.02] transition-all w-full text-left group"
          style={{ borderColor: 'rgba(16,185,129,0.15)' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider mb-1">Verified</p>
              <p className="text-3xl font-bold text-emerald-400">
                {overview?.verified || 0}
              </p>
            </div>
            <div className="w-11 h-11 rounded-lg flex items-center justify-center" style={{ background: 'rgba(16,185,129,0.1)' }}>
              <TrendingUp className="w-5 h-5 text-emerald-400" />
            </div>
          </div>
        </button>

        <button
          onClick={() => navigate(`/findings?status=false_positive${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
          className="card hover:scale-[1.02] transition-all w-full text-left group"
          style={{ borderColor: 'rgba(139,92,246,0.15)' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-xs font-semibold uppercase tracking-wider mb-1">False Positives</p>
              <p className="text-3xl font-bold text-violet-400">
                {overview?.falsePositives || 0}
              </p>
            </div>
            <div className="w-11 h-11 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.1)' }}>
              <Clock className="w-5 h-5 text-violet-400" />
            </div>
          </div>
        </button>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Criticality Distribution — clickable boxes */}
        <div className="card flex flex-col">
          <h3 className="text-base font-semibold mb-6 text-gray-200">Findings by Criticality</h3>
          <div className="grid grid-cols-5 gap-3 flex-1">
            {criticalityDataAll.map((entry) => {
              const pct = criticalityTotal > 0 ? ((entry.value / criticalityTotal) * 100).toFixed(0) : '0';
              const isClickable = entry.value > 0;
              return (
                <button
                  key={entry.key}
                  onClick={() => navigate(`/findings?criticality=${entry.key}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                  disabled={!isClickable}
                  title={isClickable ? `View ${entry.name} findings` : `No ${entry.name} findings`}
                  className="flex flex-col items-center justify-center p-4 rounded-lg border transition-all duration-200 group"
                  style={{
                    borderColor: isClickable ? `${entry.color}30` : 'rgba(255,255,255,0.05)',
                    backgroundColor: isClickable ? `${entry.color}08` : 'rgba(0,0,0,0.15)',
                    cursor: isClickable ? 'pointer' : 'default',
                    opacity: isClickable ? 1 : 0.4,
                  }}
                  onMouseEnter={e => {
                    if (isClickable) {
                      (e.currentTarget as HTMLElement).style.borderColor = `${entry.color}60`;
                      (e.currentTarget as HTMLElement).style.backgroundColor = `${entry.color}12`;
                      (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 16px ${entry.color}15`;
                    }
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLElement).style.borderColor = isClickable ? `${entry.color}30` : 'rgba(255,255,255,0.05)';
                    (e.currentTarget as HTMLElement).style.backgroundColor = isClickable ? `${entry.color}08` : 'rgba(0,0,0,0.15)';
                    (e.currentTarget as HTMLElement).style.boxShadow = 'none';
                  }}
                >
                  <div className="w-2.5 h-2.5 rounded-full mb-3 transition-transform group-hover:scale-125"
                    style={{ backgroundColor: entry.color }}
                  />
                  <span className="text-xs uppercase font-semibold tracking-wider mb-3" style={{ color: entry.color }}>
                    {entry.name}
                  </span>
                  <span className="text-3xl font-bold leading-none mb-2"
                    style={{ color: entry.color }}>
                    {entry.value}
                  </span>
                  <span className="text-xs opacity-50 font-mono" style={{ color: entry.color }}>
                    {pct}%
                  </span>
                  {isClickable && (
                    <span className="mt-3 text-xs opacity-0 group-hover:opacity-60 transition-opacity font-medium"
                      style={{ color: entry.color }}>
                      View →
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Top Finding Categories */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-gray-200">Finding Categories</h3>
            {topTypes.length > 0 && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
                <span className="text-sm font-bold text-blue-400">{topTypes.length}</span>
                <span className="text-xs text-gray-400">unique</span>
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
                    key={item.id}
                    onClick={() => {
                      navigate(`/findings?type=MACRO_${item.id}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`);
                    }}
                    title={`View all ${item.name} findings`}
                    className="w-full flex items-center gap-3 p-2.5 rounded-lg border transition-all text-left group"
                    style={{ background: 'rgba(17,24,39,0.5)', borderColor: 'rgba(255,255,255,0.06)' }}
                    onMouseEnter={e => {
                      (e.currentTarget as HTMLElement).style.borderColor = 'rgba(139,92,246,0.3)';
                      (e.currentTarget as HTMLElement).style.background = 'rgba(139,92,246,0.05)';
                    }}
                    onMouseLeave={e => {
                      (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.06)';
                      (e.currentTarget as HTMLElement).style.background = 'rgba(17,24,39,0.5)';
                    }}
                  >
                    <span className="text-gray-500 font-semibold text-sm w-5 text-right flex-shrink-0">#{index + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-gray-300 text-xs uppercase tracking-wider truncate font-semibold">
                          {item.name}
                        </span>
                        <span className="text-white font-bold text-sm ml-2 flex-shrink-0">
                          {item.count}
                        </span>
                      </div>
                      <div className="w-full rounded-full h-1" style={{ background: 'rgba(255,255,255,0.06)' }}>
                        <div
                          className="h-1 rounded-full transition-all"
                          style={{ width: `${pct}%`, background: 'linear-gradient(90deg, #3B82F6 0%, #8B5CF6 100%)' }}
                        />
                      </div>
                    </div>
                    <span className="opacity-0 group-hover:opacity-70 transition-opacity text-xs flex-shrink-0" style={{ color: '#8B5CF6' }}>→</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              NO DATA AVAILABLE
            </div>
          )}
        </div>
      </div>

      {/* Top Emails and Critical Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Extracted Emails */}
        <div className="card" style={{ borderColor: 'rgba(139,92,246,0.12)' }}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-gray-200">Top Extracted Emails</h3>
            {totalUniqueEmails > 0 && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg" style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.15)' }}>
                <span className="text-sm font-bold text-violet-400">{totalUniqueEmails}</span>
                <span className="text-xs text-gray-400">unique</span>
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
                  className="w-full flex items-center justify-between p-3 rounded-lg border transition-all text-left group"
                  style={{ background: 'rgba(17,24,39,0.5)', borderColor: 'rgba(255,255,255,0.06)' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(139,92,246,0.3)'; (e.currentTarget as HTMLElement).style.background = 'rgba(139,92,246,0.05)'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.06)'; (e.currentTarget as HTMLElement).style.background = 'rgba(17,24,39,0.5)'; }}
                >
                  <div className="flex items-center space-x-3 flex-1 min-w-0">
                    <span className="text-gray-500 font-semibold text-sm">#{index + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-gray-200 font-mono text-sm truncate">{item.email}</div>
                      <div className="text-gray-500 text-xs mt-1">
                        Found in {item.repos} repositories
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="px-2.5 py-1 rounded-md" style={{ background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.2)' }}>
                      <span className="text-violet-400 font-bold text-sm">{item.count}</span>
                    </div>
                    <span className="text-violet-400 opacity-0 group-hover:opacity-70 transition-opacity text-xs">View →</span>
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              NO EMAILS FOUND
            </div>
          )}
        </div>

        {/* Top Critical + High Findings */}
        <div className="card" style={{ borderColor: 'rgba(239,68,68,0.12)' }}>
          <h3 className="text-base font-semibold mb-4 text-gray-200">
            Top Critical &amp; High Findings
          </h3>
          {criticalFindings?.findings && criticalFindings.findings.length > 0 ? (
            <div className="space-y-3">
              {(() => {
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
                      className="w-full p-3 rounded-lg border transition-all text-left group"
                      style={{ background: 'rgba(17,24,39,0.5)', borderColor: 'rgba(255,255,255,0.06)' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(239,68,68,0.3)'; (e.currentTarget as HTMLElement).style.background = 'rgba(239,68,68,0.04)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(255,255,255,0.06)'; (e.currentTarget as HTMLElement).style.background = 'rgba(17,24,39,0.5)'; }}
                    >
                      <div className="flex items-start space-x-2 mb-2">
                        <span className="text-gray-500 font-semibold">#{index + 1}</span>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <span
                              className={`px-2 py-0.5 rounded-md text-xs uppercase font-semibold border ${isCritical
                                ? 'bg-red-500/10 border-red-500/30 text-red-400'
                                : 'bg-orange-500/10 border-orange-500/30 text-orange-400'
                                }`}
                            >
                              {isCritical ? '🔴 CRITICAL' : '🟠 HIGH'}
                            </span>
                            <span
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/findings?type=${encodeURIComponent(finding.primaryType)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`);
                              }}
                              title={`Filter by ${finding.primaryType ? finding.primaryType.replace(/_/g, ' ') : 'UNKNOWN'}`}
                              className="px-2 py-0.5 rounded-md text-xs uppercase font-semibold text-violet-400 cursor-pointer hover:bg-violet-500/20 hover:border-violet-500/40 transition-colors"
                              style={{ background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.2)', cursor: 'pointer' }}
                            >
                              {finding.primaryType ? finding.primaryType.replace(/_/g, ' ') : 'UNKNOWN'}
                            </span>
                            <span className="text-blue-400 text-xs font-bold">
                              {finding.score.toFixed(1)}
                            </span>
                            <span className="ml-auto text-gray-500 opacity-0 group-hover:opacity-70 transition-opacity text-xs">View →</span>
                          </div>
                          <div className="text-gray-300 font-mono text-xs mb-1">
                            {finding.repository} - {finding.filePath === finding.commitSha ? 'commit metadata' : finding.filePath}
                          </div>
                          <div className="p-2 rounded-md" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div className="text-gray-400 font-mono text-xs truncate">
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
            <div className="flex items-center justify-center h-64 text-gray-500">
              NO CRITICAL OR HIGH FINDINGS
            </div>
          )}
        </div>
      </div>

      {/* Top Repositories and Top Files */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Repositories */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-gray-200">Top Repositories</h3>
            {stats?.uniqueRepositories > 0 && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
                <span className="text-sm font-bold text-blue-400">{stats.uniqueRepositories}</span>
                <span className="text-xs text-gray-400">unique</span>
              </span>
            )}
          </div>
          {topRepos.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topRepos} layout="vertical" margin={{ left: 20 }}>
                <XAxis
                  type="number"
                  stroke="#4B5563"
                  tick={{ fill: '#9CA3AF', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}
                  axisLine={{ stroke: '#374151', strokeWidth: 1 }}
                />
                <YAxis
                  dataKey="repository"
                  type="category"
                  width={150}
                  stroke="#4B5563"
                  tick={{ fill: '#D1D5DB', fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}
                  axisLine={{ stroke: '#374151', strokeWidth: 1 }}
                  style={{ cursor: 'pointer' }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    fontFamily: 'JetBrains Mono, monospace',
                    color: '#F9FAFB',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                    fontSize: '12px',
                  }}
                  cursor={{ fill: 'rgba(59, 130, 246, 0.06)' }}
                />
                <Bar
                  dataKey="count"
                  fill="url(#colorGradientRepos)"
                  radius={[0, 6, 6, 0]}
                  style={{ cursor: 'pointer' }}
                  onClick={(data: any) => navigate(`/findings?repository=${encodeURIComponent(data.repository)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                />
                <defs>
                  <linearGradient id="colorGradientRepos" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#3B82F6" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#8B5CF6" stopOpacity={1} />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-32 text-gray-500">
              NO DATA AVAILABLE
            </div>
          )}
        </div>

        {/* Top Files */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-semibold text-gray-200">Top Files</h3>
            {stats?.uniqueFiles > 0 && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg" style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)' }}>
                <span className="text-sm font-bold text-blue-400">{stats.uniqueFiles}</span>
                <span className="text-xs text-gray-400">unique</span>
              </span>
            )}
          </div>
          {topFiles.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topFiles} layout="vertical" margin={{ left: 20 }}>
                <XAxis
                  type="number"
                  stroke="#4B5563"
                  tick={{ fill: '#9CA3AF', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}
                  axisLine={{ stroke: '#374151', strokeWidth: 1 }}
                />
                <YAxis
                  dataKey="filePath"
                  type="category"
                  width={150}
                  stroke="#4B5563"
                  tick={{ fill: '#D1D5DB', fontFamily: 'JetBrains Mono, monospace', fontSize: 10 }}
                  axisLine={{ stroke: '#374151', strokeWidth: 1 }}
                  style={{ cursor: 'pointer' }}
                  tickFormatter={(val: string) => val.split('/').pop() || val}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    fontFamily: 'JetBrains Mono, monospace',
                    color: '#F9FAFB',
                    boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                    fontSize: '12px',
                  }}
                  cursor={{ fill: 'rgba(59, 130, 246, 0.06)' }}
                  formatter={(value: any) => [value, 'Count']}
                  labelFormatter={(label: any) => `File: ${label}`}
                />
                <Bar
                  dataKey="count"
                  fill="url(#colorGradientFiles)"
                  radius={[0, 6, 6, 0]}
                  style={{ cursor: 'pointer' }}
                  onClick={(data: any) => navigate(`/findings?search=${encodeURIComponent(data.filePath)}${selectedDomain ? `&domain=${encodeURIComponent(selectedDomain)}` : ''}`)}
                />
                <defs>
                  <linearGradient id="colorGradientFiles" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#10B981" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#3B82F6" stopOpacity={1} />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-32 text-gray-500">
              NO DATA AVAILABLE
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <h3 className="text-base font-semibold mb-4 text-gray-200">Recent Scans</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                <th className="pb-3 text-gray-400 uppercase tracking-wider text-xs font-semibold">Domain</th>
                <th className="pb-3 text-gray-400 uppercase tracking-wider text-xs font-semibold">Status</th>
                <th className="pb-3 text-gray-400 uppercase tracking-wider text-xs font-semibold">Findings</th>
                <th className="pb-3 text-gray-400 uppercase tracking-wider text-xs font-semibold">Critical</th>
                <th className="pb-3 text-gray-400 uppercase tracking-wider text-xs font-semibold">Date</th>
              </tr>
            </thead>
            <tbody>
              {scansData?.scans?.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => scan.status === 'COMPLETED' && navigate(`/findings?scanId=${scan.id}`)}
                  title={scan.status === 'COMPLETED' ? `View findings for this scan` : undefined}
                  className={`transition-colors ${scan.status === 'COMPLETED'
                    ? 'hover:bg-white/[0.02] cursor-pointer'
                    : ''
                    }`}
                  style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                >
                  <td className="py-3 text-gray-200 font-medium text-sm font-mono">
                    {scan.domain?.name}
                  </td>
                  <td className="py-3">
                    <span
                      className={`px-2.5 py-1 rounded-md text-xs font-semibold ${scan.status === 'COMPLETED'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : scan.status === 'RUNNING'
                          ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-subtle-pulse'
                          : scan.status === 'FAILED'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : 'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                        }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-3 text-white font-bold text-sm">{scan.totalFindings}</td>
                  <td className="py-3">
                    <span className="text-red-400 font-bold">{scan.criticalCount}</span>
                  </td>
                  <td className="py-3 text-gray-500 text-sm font-mono">
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
