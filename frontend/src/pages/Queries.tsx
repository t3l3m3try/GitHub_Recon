import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  queriesAPI,
  domainAPI,
  CatalogArea,
  CatalogTarget,
  QueryCatalog,
} from '../lib/api';
import {
  Search,
  ChevronRight,
  ChevronDown,
  RotateCcw,
  Save,
  X,
  AlertTriangle,
  Code2,
  GitCommit,
  MessageSquare,
  Loader2,
  Fingerprint,
  ListFilter,
} from 'lucide-react';
import DetectionPatterns from './DetectionPatterns';

/**
 * Queries — granular control over which GitHub searches every scan performs.
 * Queries are grouped target → macro area → query. Toggles are held in local
 * draft state and committed in a single bulk PUT so that "Disable all" is one
 * request rather than hundreds.
 */

const TARGET_ICONS: Record<string, typeof Code2> = {
  code: Code2,
  commits: GitCommit,
  issues: MessageSquare,
};

type CheckState = 'checked' | 'unchecked' | 'indeterminate';

function checkState(enabled: number, total: number): CheckState {
  if (total === 0 || enabled === 0) return 'unchecked';
  if (enabled === total) return 'checked';
  return 'indeterminate';
}

function TriCheckbox({
  state,
  onChange,
  size = 'md',
}: {
  state: CheckState;
  onChange: () => void;
  size?: 'sm' | 'md';
}) {
  const box = size === 'sm' ? 'w-4 h-4' : 'w-[18px] h-[18px]';
  const active = state !== 'unchecked';

  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={state === 'indeterminate' ? 'mixed' : state === 'checked'}
      onClick={(e) => {
        e.stopPropagation();
        onChange();
      }}
      className={`${box} shrink-0 rounded flex items-center justify-center transition-all duration-150`}
      style={{
        background: active ? 'rgba(59, 130, 246, 0.9)' : 'rgba(17, 24, 39, 0.8)',
        border: `1px solid ${active ? 'rgba(96, 165, 250, 0.6)' : 'rgba(255,255,255,0.15)'}`,
      }}
    >
      {state === 'checked' && (
        <svg viewBox="0 0 16 16" className="w-3 h-3" fill="none" stroke="#fff" strokeWidth="2.5">
          <path d="M3 8.5l3.5 3.5L13 4.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
      {state === 'indeterminate' && <div className="w-2 h-[2px] rounded-full bg-white" />}
    </button>
  );
}

export default function Queries() {
  const queryClient = useQueryClient();

  const [tab, setTab] = useState<'queries' | 'patterns'>('queries');
  const [search, setSearch] = useState('');
  const [previewDomain, setPreviewDomain] = useState<string>('');
  const [collapsedTargets, setCollapsedTargets] = useState<Record<string, boolean>>({});
  const [expandedAreas, setExpandedAreas] = useState<Record<string, boolean>>({});
  /** queryId → enabled, only for entries that diverge from the server state */
  const [draft, setDraft] = useState<Record<string, boolean>>({});

  const { data: domains } = useQuery({
    queryKey: ['domains'],
    queryFn: async () => (await domainAPI.getAll()).data,
  });

  const effectiveDomain = previewDomain || domains?.[0]?.name || '';

  const { data: catalog, isLoading } = useQuery({
    queryKey: ['queries', effectiveDomain],
    queryFn: async () => (await queriesAPI.getAll(effectiveDomain || undefined)).data,
  });

  const applyCatalog = (next: QueryCatalog) => {
    queryClient.setQueryData(['queries', effectiveDomain], next);
    queryClient.invalidateQueries({ queryKey: ['queries'] });
    setDraft({});
  };

  const saveMutation = useMutation({
    mutationFn: async (updates: { queryId: string; enabled: boolean }[]) =>
      (await queriesAPI.update(updates, effectiveDomain || undefined)).data,
    onSuccess: applyCatalog,
  });

  const resetMutation = useMutation({
    mutationFn: async () => (await queriesAPI.reset(effectiveDomain || undefined)).data,
    onSuccess: applyCatalog,
  });

  /** Enabled state for a query, draft taking precedence over the server value. */
  const isEnabled = (queryId: string, serverEnabled: boolean) =>
    draft[queryId] ?? serverEnabled;

  const term = search.trim().toLowerCase();

  /** The catalog narrowed to rows matching the search box. */
  const filtered = useMemo(() => {
    if (!catalog) return [];
    return catalog.targets.map((target) => ({
      ...target,
      areas: target.areas
        .map((area) => ({
          ...area,
          queries: term
            ? area.queries.filter(
                (q) =>
                  q.label.toLowerCase().includes(term) ||
                  q.preview.toLowerCase().includes(term) ||
                  q.template.toLowerCase().includes(term)
              )
            : area.queries,
        }))
        .filter((area) => area.queries.length > 0 || (!term && area.queries.length === 0)),
    }));
  }, [catalog, term]);

  /** Live counts that reflect unsaved draft toggles. */
  const counts = useMemo(() => {
    const perTarget: Record<string, { enabled: number; total: number }> = {};
    const perArea: Record<string, { enabled: number; total: number }> = {};
    let enabled = 0;
    let total = 0;

    for (const target of catalog?.targets ?? []) {
      let tEnabled = 0;
      let tTotal = 0;
      for (const area of target.areas) {
        let aEnabled = 0;
        for (const q of area.queries) {
          if (isEnabled(q.id, q.enabled)) aEnabled++;
        }
        perArea[`${target.id}/${area.id}`] = { enabled: aEnabled, total: area.queries.length };
        tEnabled += aEnabled;
        tTotal += area.queries.length;
      }
      perTarget[target.id] = { enabled: tEnabled, total: tTotal };
      enabled += tEnabled;
      total += tTotal;
    }
    return { perTarget, perArea, enabled, total };
  }, [catalog, draft]);

  const dirtyCount = Object.keys(draft).length;

  /** Toggle a set of query ids to a fixed value, dropping no-op entries. */
  const setMany = (rows: { id: string; serverEnabled: boolean }[], enabled: boolean) => {
    setDraft((prev) => {
      const next = { ...prev };
      for (const row of rows) {
        if (row.serverEnabled === enabled) delete next[row.id];
        else next[row.id] = enabled;
      }
      return next;
    });
  };

  const toggleArea = (target: CatalogTarget, area: CatalogArea) => {
    const state = checkState(
      counts.perArea[`${target.id}/${area.id}`]?.enabled ?? 0,
      area.queries.length
    );
    setMany(
      area.queries.map((q) => ({ id: q.id, serverEnabled: q.enabled })),
      state !== 'checked'
    );
  };

  const toggleTarget = (target: CatalogTarget) => {
    const state = checkState(
      counts.perTarget[target.id]?.enabled ?? 0,
      counts.perTarget[target.id]?.total ?? 0
    );
    setMany(
      target.areas.flatMap((a) => a.queries.map((q) => ({ id: q.id, serverEnabled: q.enabled }))),
      state !== 'checked'
    );
  };

  const setAll = (enabled: boolean) => {
    setMany(
      (catalog?.targets ?? []).flatMap((t) =>
        t.areas.flatMap((a) => a.queries.map((q) => ({ id: q.id, serverEnabled: q.enabled })))
      ),
      enabled
    );
  };

  const handleSave = () => {
    saveMutation.mutate(
      Object.entries(draft).map(([queryId, enabled]) => ({ queryId, enabled }))
    );
  };

  const handleReset = () => {
    if (confirm('Re-enable all queries and discard your selection?')) {
      setDraft({});
      resetMutation.mutate();
    }
  };

  const emptyTargets = (catalog?.targets ?? []).filter(
    (t) => (counts.perTarget[t.id]?.enabled ?? 0) === 0
  );

  const TabButton = ({
    id,
    icon: Icon,
    label,
  }: {
    id: 'queries' | 'patterns';
    icon: typeof ListFilter;
    label: string;
  }) => (
    <button
      type="button"
      onClick={() => setTab(id)}
      className="flex items-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-lg transition-colors"
      style={
        tab === id
          ? { background: 'rgba(59,130,246,0.15)', color: '#60a5fa', border: '1px solid rgba(96,165,250,0.35)' }
          : { background: 'transparent', color: '#9ca3af', border: '1px solid transparent' }
      }
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );

  return (
    <div className="space-y-6 pb-28">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-3xl font-bold mb-1 page-title">Queries</h2>
          <p className="text-gray-400 text-sm">
            {tab === 'queries'
              ? 'Control exactly which GitHub searches every scan performs.'
              : 'The regex patterns every scan uses to extract secrets from what those searches return. Read-only — these are intrinsic to the detection engine, not toggleable per scan.'}
          </p>
        </div>
        {tab === 'queries' && (
          <div className="text-right">
            <div className="text-2xl font-bold text-blue-400">
              {counts.enabled} <span className="text-gray-500 text-lg">/ {counts.total}</span>
            </div>
            <div className="text-xs text-gray-500 uppercase tracking-wider">Queries enabled</div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 card !p-1.5 w-fit">
        <TabButton id="queries" icon={ListFilter} label="Search Queries" />
        <TabButton id="patterns" icon={Fingerprint} label="Detection Patterns" />
      </div>

      {tab === 'patterns' ? (
        <DetectionPatterns />
      ) : isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-lg text-gray-400 animate-subtle-pulse">Loading queries...</div>
        </div>
      ) : (
        <>
      {/* Toolbar */}
      <div className="card">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              className="input pl-9"
              placeholder="Search queries by name or syntax..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="input w-auto min-w-[180px]"
            value={effectiveDomain}
            onChange={(e) => setPreviewDomain(e.target.value)}
            title="Preview the queries as they will be sent for this domain"
          >
            {(domains ?? []).length === 0 && <option value="">No domains added</option>}
            {(domains ?? []).map((d) => (
              <option key={d.id} value={d.name}>
                Preview: {d.name}
              </option>
            ))}
          </select>

          <button className="btn btn-secondary" onClick={() => setAll(true)}>
            Enable all
          </button>
          <button className="btn btn-secondary" onClick={() => setAll(false)}>
            Disable all
          </button>
          <button
            className="btn btn-secondary flex items-center space-x-2"
            onClick={handleReset}
            disabled={resetMutation.isPending}
          >
            <RotateCcw className="w-4 h-4" />
            <span>{resetMutation.isPending ? 'Resetting...' : 'Reset defaults'}</span>
          </button>
        </div>
      </div>

      {/* Warnings */}
      {counts.enabled === 0 ? (
        <div
          className="rounded-lg p-4 flex items-start space-x-3"
          style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}
        >
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="text-red-300 font-bold text-sm">No queries enabled</div>
            <div className="text-red-400/70 text-sm">
              Scans cannot run until at least one query is enabled.
            </div>
          </div>
        </div>
      ) : (
        emptyTargets.length > 0 && (
          <div
            className="rounded-lg p-4 flex items-start space-x-3"
            style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.25)' }}
          >
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-amber-300/90 text-sm">
              {emptyTargets.map((t) => t.name).join(' and ')} will be skipped entirely — no queries
              enabled in {emptyTargets.length > 1 ? 'those sections' : 'that section'}.
            </div>
          </div>
        )
      )}

      {/* Targets */}
      {filtered.map((target) => {
        const Icon = TARGET_ICONS[target.id] ?? Code2;
        const tCount = counts.perTarget[target.id] ?? { enabled: 0, total: 0 };
        const collapsed = collapsedTargets[target.id] ?? false;
        const visibleAreas = target.areas.filter((a) => a.queries.length > 0);

        if (term && visibleAreas.length === 0) return null;

        return (
          <div key={target.id} className="card !p-0 overflow-hidden">
            {/* Target header */}
            <div
              className="flex items-center gap-3 px-5 py-4 cursor-pointer select-none"
              style={{ borderBottom: collapsed ? 'none' : '1px solid rgba(255,255,255,0.06)' }}
              onClick={() =>
                setCollapsedTargets((prev) => ({ ...prev, [target.id]: !collapsed }))
              }
            >
              {collapsed ? (
                <ChevronRight className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              )}
              <TriCheckbox
                state={checkState(tCount.enabled, tCount.total)}
                onChange={() => toggleTarget(target as CatalogTarget)}
              />
              <Icon className="w-4 h-4 text-blue-400" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">
                  {target.name}
                </div>
                <div className="text-xs text-gray-500 truncate">{target.description}</div>
              </div>
              <div className="text-sm font-bold text-gray-300 whitespace-nowrap">
                {tCount.enabled}
                <span className="text-gray-600"> / {tCount.total}</span>
              </div>
            </div>

            {/* Areas */}
            {!collapsed && (
              <div>
                {visibleAreas.map((area) => {
                  const key = `${target.id}/${area.id}`;
                  const aCount = counts.perArea[key] ?? { enabled: 0, total: 0 };
                  // Searching auto-expands so matches are visible without clicking.
                  const expanded = term ? true : expandedAreas[key] ?? false;

                  return (
                    <div key={key} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <div
                        className="flex items-center gap-3 pl-10 pr-5 py-3 cursor-pointer select-none hover:bg-white/[0.02] transition-colors"
                        onClick={() =>
                          setExpandedAreas((prev) => ({ ...prev, [key]: !expanded }))
                        }
                      >
                        {expanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-gray-600" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
                        )}
                        <TriCheckbox
                          size="sm"
                          state={checkState(aCount.enabled, aCount.total)}
                          onChange={() => toggleArea(target as CatalogTarget, area)}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-semibold text-gray-200">{area.name}</div>
                          <div className="text-xs text-gray-500 truncate">{area.description}</div>
                        </div>
                        <div className="text-xs font-bold text-gray-400 whitespace-nowrap">
                          {aCount.enabled}
                          <span className="text-gray-600"> / {aCount.total}</span>
                        </div>
                      </div>

                      {expanded && (
                        <div style={{ background: 'rgba(0,0,0,0.15)' }}>
                          {area.queries.map((q) => {
                            const enabled = isEnabled(q.id, q.enabled);
                            const changed = draft[q.id] !== undefined;
                            return (
                              <div
                                key={q.id}
                                onClick={() =>
                                  setMany([{ id: q.id, serverEnabled: q.enabled }], !enabled)
                                }
                                className="flex items-start gap-3 pl-[4.5rem] pr-5 py-2.5 cursor-pointer hover:bg-white/[0.03] transition-colors"
                                style={{
                                  borderLeft: changed
                                    ? '2px solid rgba(59,130,246,0.6)'
                                    : '2px solid transparent',
                                }}
                              >
                                <div className="pt-0.5">
                                  <TriCheckbox
                                    size="sm"
                                    state={enabled ? 'checked' : 'unchecked'}
                                    onChange={() =>
                                      setMany([{ id: q.id, serverEnabled: q.enabled }], !enabled)
                                    }
                                  />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div
                                    className={`text-sm ${enabled ? 'text-gray-200' : 'text-gray-500 line-through'}`}
                                  >
                                    {q.label}
                                  </div>
                                  <code
                                    className="block text-xs mt-0.5 break-all"
                                    style={{
                                      fontFamily: 'ui-monospace, SFMono-Regular, monospace',
                                      color: enabled ? 'rgba(148,163,184,0.85)' : 'rgba(107,114,128,0.6)',
                                    }}
                                  >
                                    {q.preview}
                                  </code>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}

      {term && filtered.every((t) => t.areas.every((a) => a.queries.length === 0)) && (
        <div className="card text-center py-12">
          <p className="text-gray-400">No queries match “{search}”.</p>
        </div>
      )}

      {/* Sticky save bar */}
      {dirtyCount > 0 && (
        <div className="fixed bottom-0 left-0 right-0 z-40 px-6 py-4" style={{
          background: 'rgba(11, 15, 25, 0.92)',
          borderTop: '1px solid rgba(59,130,246,0.25)',
          backdropFilter: 'blur(12px)',
        }}>
          <div className="container mx-auto flex items-center justify-between gap-4">
            <div className="text-sm text-gray-300">
              <span className="font-bold text-blue-400">{dirtyCount}</span> unsaved change
              {dirtyCount === 1 ? '' : 's'}
            </div>
            <div className="flex items-center gap-3">
              <button
                className="btn btn-secondary flex items-center space-x-2"
                onClick={() => setDraft({})}
                disabled={saveMutation.isPending}
              >
                <X className="w-4 h-4" />
                <span>Discard</span>
              </button>
              <button
                className="btn btn-primary flex items-center space-x-2"
                onClick={handleSave}
                disabled={saveMutation.isPending}
              >
                {saveMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                <span>{saveMutation.isPending ? 'Saving...' : 'Save Changes'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {saveMutation.isError && (
        <div className="text-red-400 text-sm">
          {(saveMutation.error as any)?.response?.data?.error || 'Failed to save query selection.'}
        </div>
      )}
        </>
      )}
    </div>
  );
}
