import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { domainAPI, scanAPI, Domain, Scan } from '../lib/api';
import { Plus, Play, Trash2, Clock, CheckCircle, Square, RefreshCw, Loader2 } from 'lucide-react';

export default function Domains() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState({ name: '', scanFrequency: 'manual' });

  const { data: domains, isLoading } = useQuery({
    queryKey: ['domains'],
    queryFn: async () => {
      const response = await domainAPI.getAll();
      return response.data;
    },
  });

  // Fetch active scans for all domains to show status
  const { data: scansData } = useQuery({
    queryKey: ['active-scans'],
    queryFn: async () => {
      const response = await scanAPI.getAll({ limit: 50, page: 1 });
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
    mutationFn: (data: { name: string; scanFrequency: string }) =>
      domainAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains'] });
      setShowAddModal(false);
      setNewDomain({ name: '', scanFrequency: 'manual' });
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
    if (newDomain.name) {
      createMutation.mutate(newDomain);
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
        <div className="text-xl neon-text cyber-pulse">LOADING DOMAINS...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-4xl font-bold mb-2 neon-text uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Domains</h2>
          <p className="text-cyan-400" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Manage domains to monitor for security findings</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="btn btn-primary flex items-center space-x-2"
        >
          <Plus className="w-5 h-5" />
          <span>Add Domain</span>
        </button>
      </div>

      {/* Domains Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {domains?.map((domain) => {
          const scanning = isDomainScanning(domain.id);
          const latestScan = getLatestScan(domain.id);

          return (
            <div key={domain.id} className={`card ${scanning ? 'neon-box-blue' : 'neon-box'} hover:scale-105 transition-transform`}>
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-2xl font-bold text-cyan-300" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 10px var(--cyber-cyan)' }}>{domain.name}</h3>
                    {scanning ? (
                      <Loader2 className="w-6 h-6 text-blue-400 animate-spin" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-blue))' }} />
                    ) : domain.active ? (
                      <CheckCircle className="w-6 h-6 text-cyan-400 cyber-pulse" style={{ filter: 'drop-shadow(0 0 8px var(--cyber-cyan))' }} />
                    ) : (
                      <Clock className="w-6 h-6 text-blue-500" />
                    )}
                  </div>
                  <div className="text-sm text-cyan-400/70 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                    Scan Frequency: {domain.scanFrequency}
                  </div>
                </div>

                {/* Scan Progress */}
                {scanning && latestScan && (
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded-sm p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                        <span className="text-blue-300 text-sm font-bold uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                          {latestScan.status === 'QUEUED' ? 'Queued' : latestScan.progress ? getPhaseLabel(latestScan.progress.phase) : 'Scanning'}
                        </span>
                      </div>
                      {latestScan.progress && (
                        <span className="text-blue-200 text-sm font-bold" style={{ fontFamily: 'Orbitron, monospace', textShadow: '0 0 8px rgba(96, 165, 250, 0.8)' }}>
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
                          <p className="text-blue-400/70 text-xs truncate flex-1" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                            {latestScan.progress.message}
                          </p>
                          {latestScan.progress.findings > 0 && (
                            <span className="text-cyan-400 text-xs ml-2 whitespace-nowrap" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                              {latestScan.progress.findings} found
                            </span>
                          )}
                        </div>
                      </>
                    ) : (
                      <p className="text-blue-400/70 text-xs" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                        {latestScan.status === 'QUEUED' ? 'Queued, starting soon...' : 'Initializing...'}
                      </p>
                    )}
                  </div>
                )}

                {/* Latest scan result */}
                {!scanning && latestScan && latestScan.status === 'COMPLETED' && (
                  <div className="bg-cyan-900/10 border border-cyan-500/20 rounded-sm p-3">
                    <div className="text-cyan-400/70 text-xs uppercase tracking-wider mb-1" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Last Scan Result</div>
                    <div className="flex items-center space-x-3 text-sm" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                      <span className="text-cyan-300">{latestScan.totalFindings} findings</span>
                      {latestScan.criticalCount > 0 && (
                        <span className="text-purple-400 font-bold">{latestScan.criticalCount} critical</span>
                      )}
                    </div>
                  </div>
                )}

                {!scanning && latestScan && latestScan.status === 'FAILED' && (
                  <div className="bg-purple-900/10 border border-purple-500/30 rounded-sm p-3">
                    <div className="text-purple-400 text-xs uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
                      Last scan failed
                    </div>
                  </div>
                )}

                <div className="space-y-2 text-sm">
                  <div className="flex justify-between border-b border-cyan-500/20 pb-2">
                    <span className="text-cyan-400/70 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Total Scans:</span>
                    <span className="font-bold text-cyan-300" style={{ fontFamily: 'Orbitron, monospace' }}>{domain._count?.scans || 0}</span>
                  </div>
                  {domain.lastScanAt && (
                    <div className="flex justify-between">
                      <span className="text-cyan-400/70 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>Last Scan:</span>
                      <span className="font-medium text-cyan-300" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                        {new Date(domain.lastScanAt).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </div>

                <div className="flex space-x-2 pt-4 border-t border-cyan-500/30 cyber-border-top">
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
          <div className="col-span-full card neon-box text-center py-12">
            <p className="text-cyan-400 mb-4 text-lg uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>No domains added yet</p>
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
            className="card neon-box-blue max-w-md w-full"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-2xl font-bold mb-4 neon-text uppercase tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>Add New Domain</h3>
            <form onSubmit={handleAddDomain} className="space-y-4">
              <div>
                <label className="block text-sm text-cyan-400 mb-2 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
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
                <p className="text-xs text-cyan-400/60 mt-1" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
                  Enter the domain you want to monitor (e.g., company.com)
                </p>
              </div>

              <div>
                <label className="block text-sm text-cyan-400 mb-2 uppercase tracking-wider" style={{ fontFamily: 'Rajdhani, sans-serif' }}>
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
                  disabled={createMutation.isPending}
                  className="flex-1 btn btn-primary"
                >
                  {createMutation.isPending ? 'Adding...' : 'Add Domain'}
                </button>
              </div>

              {createMutation.isError && (
                <div className="text-purple-400 text-sm mt-2 border border-purple-500/50 rounded p-2 bg-purple-900/20" style={{ fontFamily: 'Share Tech Mono, monospace' }}>
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
