import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { domainAPI, scanAPI, Domain, Scan } from '../lib/api';
import { Plus, Play, Trash2, Clock, CheckCircle, Square, RefreshCw, Loader2, Building2 } from 'lucide-react';
import { useOrgFilter } from '../contexts/OrgFilterContext';

export default function Domains() {
  const queryClient = useQueryClient();
  const { orgId, setOrgId, organizations } = useOrgFilter();
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState({ name: '', scanFrequency: 'manual', orgId: '' });

  const { data: domains, isLoading } = useQuery({
    queryKey: ['domains', orgId],
    queryFn: async () => {
      const response = await domainAPI.getAll(orgId ? { orgId } : undefined);
      return response.data;
    },
  });

  // Fetch active scans for all domains to show status
  const { data: scansData } = useQuery({
    queryKey: ['active-scans', orgId],
    queryFn: async () => {
      const params: any = { limit: 50, page: 1 };
      if (orgId) params.orgId = orgId;
      const response = await scanAPI.getAll(params);
      return response.data;
    },
    refetchInterval: (query) => {
      const data = query.state.data as any;
      const hasRunning = data?.scans?.some((s: any) => s.status === 'RUNNING' || s.status === 'QUEUED');
      return hasRunning ? 5000 : false;
    },
  });

  // Build a map of domain -> latest scan
  const domainScanMap: Record<string, Scan> = {};
  if (scansData?.scans) {
    for (const scan of scansData.scans) {
      if (!domainScanMap[scan.domainId]) {
        domainScanMap[scan.domainId] = scan;
      }
    }
  }

  const createMutation = useMutation({
    mutationFn: (data: { name: string; scanFrequency: string; orgId?: string }) =>
      domainAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains'] });
      setShowAddModal(false);
      setNewDomain({ name: '', scanFrequency: 'manual', orgId: '' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => domainAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains'] });
    },
  });

  const scanMutation = useMutation({
    mutationFn: (domainId: string) => scanAPI.create({ domainId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['active-scans'] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => scanAPI.cancel(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['active-scans'] });
    },
  });

  const handleAddDomain = (e: React.FormEvent) => {
    e.preventDefault();
    if (newDomain.name && (organizations.length === 0 || newDomain.orgId)) {
      createMutation.mutate(organizations.length > 0 ? newDomain : { name: newDomain.name, scanFrequency: newDomain.scanFrequency });
    }
  };

  const handleStartScan = (domain: Domain) => {
    scanMutation.mutate(domain.id);
  };

  const handleStopScan = (scanId: string) => {
    cancelMutation.mutate(scanId);
  };

  const handleDeleteDomain = (domain: Domain) => {
    if (confirm(`Delete domain ${domain.name}? This will also delete all associated scans and findings.`)) {
      deleteMutation.mutate(domain.id);
    }
  };

  const isDomainScanning = (domainId: string): boolean => {
    const scan = domainScanMap[domainId];
    return scan?.status === 'RUNNING' || scan?.status === 'QUEUED';
  };

  const getLatestScan = (domainId: string): Scan | undefined => {
    return domainScanMap[domainId];
  };

  const getPhaseLabel = (phase: string): string => {
    switch (phase) {
      case 'init': return 'Initializing';
      case 'code': return 'Code Search';
      case 'commits': return 'Commit Search';
      case 'issues': return 'Issue Search';
      case 'complete': return 'Finalizing';
      default: return phase;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-gray-400 animate-subtle-pulse">Loading domains...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-3xl font-bold mb-1 page-title" >Domains</h2>
          <p className="text-gray-400 text-sm" >
            {organizations.length > 0 && !orgId
              ? 'Manage domains across all organizations'
              : 'Manage domains to monitor for security findings'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {organizations.length > 0 && (
            <select
              className="input"
              style={{ minWidth: '200px' }}
              value={orgId}
              onChange={(e) => setOrgId(e.target.value)}
            >
              <option value="">All Organizations</option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id}>{org.name}</option>
              ))}
            </select>
          )}
          <button
            onClick={() => { setNewDomain(d => ({ ...d, orgId })); setShowAddModal(true); }}
            className="btn btn-primary flex items-center space-x-2"
          >
            <Plus className="w-5 h-5" />
            <span>Add Domain</span>
          </button>
        </div>
      </div>

      {/* Domains Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {domains?.map((domain) => {
          const scanning = isDomainScanning(domain.id);
          const latestScan = getLatestScan(domain.id);

          return (
            <div key={domain.id} className={`card hover:scale-[1.02] transition-all`} style={{ borderColor: scanning ? 'rgba(59,130,246,0.2)' : undefined }}>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xl font-bold text-white">{domain.name}</h3>
                    {scanning ? (
                      <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
                    ) : domain.active ? (
                      <CheckCircle className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <Clock className="w-5 h-5 text-gray-500" />
                    )}
                  </div>
                  <div className="text-xs text-gray-500 uppercase tracking-wider" >
                    Scan Frequency: {domain.scanFrequency}
                  </div>
                  {organizations.length > 0 && domain.organization?.name && (
                    <div className="flex items-center gap-1 text-xs text-violet-400 mt-1.5">
                      <Building2 className="w-3 h-3" />
                      <span>{domain.organization.name}</span>
                    </div>
                  )}
                </div>

                {/* Scan Progress */}
                {scanning && latestScan && (
                  <div className="rounded-lg p-3 space-y-2" style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)' }}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                        <span className="text-blue-300 text-sm font-bold uppercase tracking-wider" >
                          {latestScan.status === 'QUEUED' ? 'Queued' : latestScan.progress ? getPhaseLabel(latestScan.progress.phase) : 'Scanning'}
                        </span>
                      </div>
                      {latestScan.progress && (
                        <span className="text-blue-400 text-sm font-bold" style={{ textShadow: 'none' }}>
                          {latestScan.progress.percent}%
                        </span>
                      )}
                    </div>
                    {/* Progress Bar */}
                    {latestScan.progress ? (
                      <>
                        <div className="w-full h-2 bg-gray-800/80 rounded-full overflow-hidden border border-blue-500/20">
                          <div
                            className="h-full rounded-full transition-all duration-700 ease-out"
                            style={{
                              width: `${latestScan.progress.percent}%`,
                              background: 'linear-gradient(90deg, #06b6d4, #3b82f6, #8b5cf6)',
                              boxShadow: '0 0 10px rgba(59, 130, 246, 0.6), 0 0 20px rgba(59, 130, 246, 0.3)',
                            }}
                          />
                        </div>
                        <div className="flex items-center justify-between">
                          <p className="text-blue-400/70 text-xs truncate flex-1" >
                            {latestScan.progress.message}
                          </p>
                          {latestScan.progress.findings > 0 && (
                            <span className="text-gray-400 text-xs ml-2 whitespace-nowrap" >
                              {latestScan.progress.findings} found
                            </span>
                          )}
                        </div>
                      </>
                    ) : (
                      <p className="text-blue-400/70 text-xs" >
                        {latestScan.status === 'QUEUED' ? 'Queued, starting soon...' : 'Initializing...'}
                      </p>
                    )}
                  </div>
                )}

                {/* Latest scan result */}
                {!scanning && latestScan && latestScan.status === 'COMPLETED' && (
                  <div className="bg-white/[0.03] border border-gray-700/50 rounded-sm p-3">
                    <div className="text-gray-400 text-xs uppercase tracking-wider mb-1" >Last Scan Result</div>
                    <div className="flex items-center space-x-3 text-sm" >
                      <span className="text-gray-200">{latestScan.totalFindings} findings</span>
                      {latestScan.criticalCount > 0 && (
                        <span className="text-red-400 font-bold">{latestScan.criticalCount} critical</span>
                      )}
                    </div>
                  </div>
                )}

                {!scanning && latestScan && latestScan.status === 'FAILED' && (
                  <div className="bg-red-500/5 border border-red-500/20 rounded-sm p-3">
                    <div className="text-red-400 text-xs uppercase tracking-wider" >
                      Last scan failed
                    </div>
                  </div>
                )}

                <div className="space-y-2 text-sm">
                  <div className="flex justify-between border-b border-gray-700/50 pb-2">
                    <span className="text-gray-400 uppercase tracking-wider" >Total Scans:</span>
                    <span className="font-bold text-gray-200" >{domain._count?.scans || 0}</span>
                  </div>
                  {domain.lastScanAt && (
                    <div className="flex justify-between">
                      <span className="text-gray-400 uppercase tracking-wider" >Last Scan:</span>
                      <span className="font-medium text-gray-200" >
                        {new Date(domain.lastScanAt).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </div>

                <div className="flex space-x-2 pt-4" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  {scanning ? (
                    <button
                      onClick={() => latestScan && handleStopScan(latestScan.id)}
                      disabled={cancelMutation.isPending}
                      className="flex-1 btn flex items-center justify-center space-x-1 bg-gradient-to-r from-purple-500/20 to-magenta-500/20 text-purple-300 border border-purple-500/50 hover:border-purple-400 transition-all"
                    >
                      <Square className="w-4 h-4" />
                      <span>{cancelMutation.isPending ? 'Stopping...' : 'Stop Scan'}</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleStartScan(domain)}
                      disabled={scanMutation.isPending}
                      className="flex-1 btn btn-primary flex items-center justify-center space-x-1"
                    >
                      {latestScan?.status === 'COMPLETED' || latestScan?.status === 'FAILED' || latestScan?.status === 'CANCELLED' ? (
                        <>
                          <RefreshCw className="w-4 h-4" />
                          <span>{scanMutation.isPending ? 'Starting...' : 'Re-Scan'}</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4" />
                          <span>{scanMutation.isPending ? 'Starting...' : 'Scan'}</span>
                        </>
                      )}
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteDomain(domain)}
                    disabled={deleteMutation.isPending || scanning}
                    className="btn btn-danger flex items-center justify-center disabled:opacity-30"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}

        {domains?.length === 0 && (
          <div className="col-span-full card card text-center py-12">
            <p className="text-gray-400 mb-4 text-lg uppercase tracking-wider" >No domains added yet</p>
            <button
              onClick={() => setShowAddModal(true)}
              className="btn btn-primary inline-flex items-center space-x-2"
            >
              <Plus className="w-5 h-5" />
              <span>Add Your First Domain</span>
            </button>
          </div>
        )}
      </div>

      {/* Add Domain Modal */}
      {showAddModal && (
        <div
          className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center p-4 z-50"
          onClick={() => setShowAddModal(false)}
          style={{ backdropFilter: 'blur(8px)' }}
        >
          <div
            className="card card max-w-md w-full"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-bold mb-4 page-title" >Add New Domain</h3>
            <form onSubmit={handleAddDomain} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider" >
                  Domain Name *
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="example.com"
                  value={newDomain.name}
                  onChange={(e) =>
                    setNewDomain({ ...newDomain, name: e.target.value })
                  }
                  required
                />
                <p className="text-xs text-gray-500 mt-1" >
                  Enter the domain you want to monitor (e.g., company.com)
                </p>
              </div>

              {organizations.length > 0 && (
                <div>
                  <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider" >
                    Organization *
                  </label>
                  <select
                    className="input"
                    value={newDomain.orgId}
                    onChange={(e) => setNewDomain({ ...newDomain, orgId: e.target.value })}
                    required
                  >
                    <option value="">Select an organization</option>
                    {organizations.map((org) => (
                      <option key={org.id} value={org.id}>{org.name}</option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-500 mt-1" >
                    As a super admin, you must choose which organization owns this domain
                  </p>
                </div>
              )}

              <div>
                <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider" >
                  Scan Frequency
                </label>
                <select
                  className="input"
                  value={newDomain.scanFrequency}
                  onChange={(e) =>
                    setNewDomain({ ...newDomain, scanFrequency: e.target.value })
                  }
                >
                  <option value="manual">Manual</option>
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
              </div>

              <div className="flex space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 btn btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || (organizations.length > 0 && !newDomain.orgId)}
                  className="flex-1 btn btn-primary"
                >
                  {createMutation.isPending ? 'Adding...' : 'Add Domain'}
                </button>
              </div>

              {createMutation.isError && (
                <div className="text-red-400 text-sm mt-2 border border-purple-500/50 rounded p-2 bg-red-500/5" >
                  {(createMutation.error as any)?.response?.data?.error || 'Failed to add domain. Please check the format and try again.'}
                </div>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
