import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { patternsAPI } from '../lib/api';
import { Search, ChevronRight, ChevronDown, ChevronsDownUp, ChevronsUpDown, ShieldAlert } from 'lucide-react';

/**
 * Detection Patterns — read-only view of the regex patterns the scanner runs
 * against GitHub search results to extract secrets, grouped by type. This is
 * a separate stage from the search queries shown on the Search Queries tab:
 * queries decide what GitHub is asked for, these patterns decide what counts
 * as a secret in whatever comes back. Not user-configurable, so there's
 * nothing to toggle. Everything that isn't tied to one specific pattern —
 * the domain pattern, false-positive rules, criticality scoring — lives on
 * the separate Detection Settings tab instead of repeating here.
 */

export default function DetectionPatterns() {
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const { data: catalog, isLoading, isError } = useQuery({
    queryKey: ['patterns'],
    queryFn: async () => (await patternsAPI.getAll()).data,
  });

  const term = search.trim().toLowerCase();

  const filtered = useMemo(() => {
    if (!catalog) return [];
    if (!term) return catalog.groups;
    return catalog.groups
      .map((group) => ({
        ...group,
        patterns: group.patterns.filter(
          (p) =>
            p.description.toLowerCase().includes(term) ||
            p.source.toLowerCase().includes(term) ||
            group.type.toLowerCase().includes(term) ||
            p.contextKeywords.some((k) => k.toLowerCase().includes(term))
        ),
      }))
      .filter((group) => group.patterns.length > 0);
  }, [catalog, term]);

  const expandAll = () => {
    if (!catalog) return;
    const next: Record<string, boolean> = {};
    for (const g of catalog.groups) next[g.type] = true;
    setExpanded(next);
  };

  const collapseAll = () => setExpanded({});

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-gray-400 animate-subtle-pulse">Loading detection patterns...</div>
      </div>
    );
  }

  if (isError || !catalog) {
    return (
      <div className="card text-center py-12">
        <p className="text-gray-400">Failed to load detection patterns.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            className="input pl-9"
            placeholder="Search patterns by type, regex or keyword..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-3">
          <button className="btn btn-secondary flex items-center gap-2" onClick={expandAll}>
            <ChevronsUpDown className="w-4 h-4" />
            <span>Expand all</span>
          </button>
          <button className="btn btn-secondary flex items-center gap-2" onClick={collapseAll}>
            <ChevronsDownUp className="w-4 h-4" />
            <span>Collapse all</span>
          </button>
          <div className="text-right">
            <div className="text-2xl font-bold text-blue-400">{catalog.total}</div>
            <div className="text-xs text-gray-500 uppercase tracking-wider whitespace-nowrap">Detection patterns</div>
          </div>
        </div>
      </div>

      {filtered.map((group) => {
        const isExpanded = term ? true : expanded[group.type] ?? false;
        return (
          <div key={group.type} className="card !p-0 overflow-hidden">
            <div
              className="flex items-center gap-3 px-5 py-4 cursor-pointer select-none"
              style={{ borderBottom: isExpanded ? '1px solid rgba(255,255,255,0.06)' : 'none' }}
              onClick={() => setExpanded((prev) => ({ ...prev, [group.type]: !isExpanded }))}
            >
              {isExpanded ? (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-500" />
              )}
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">
                  {group.type.replace(/_/g, ' ')}
                </div>
              </div>
              <div className="text-sm font-bold text-gray-300 whitespace-nowrap w-8 text-right">{group.count}</div>
            </div>

            {isExpanded && (
              <div style={{ background: 'rgba(0,0,0,0.15)' }}>
                {group.patterns.map((p, i) => (
                  <div
                    key={`${group.type}-${i}`}
                    className="px-5 py-3"
                    style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                  >
                    <div className="text-sm text-gray-200 mb-1">{p.description}</div>
                    <code
                      className="block text-xs mb-2 break-all px-2 py-1 rounded"
                      style={{
                        fontFamily: 'ui-monospace, SFMono-Regular, monospace',
                        color: 'rgba(148,163,184,0.9)',
                        background: 'rgba(255,255,255,0.03)',
                      }}
                    >
                      /{p.source}/{p.flags}
                    </code>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                      <span className={p.entropyThreshold !== null ? 'text-gray-500' : 'text-gray-600 italic'}>
                        {p.entropyThreshold !== null ? (
                          <>
                            Entropy ≥ <span className="text-gray-400 font-semibold">{p.entropyThreshold}</span>
                          </>
                        ) : (
                          'No entropy filter'
                        )}
                      </span>
                      {p.exampleMatch && (
                        <span className="text-gray-500 truncate max-w-xs">
                          Example: <span className="text-gray-400 font-mono">{p.exampleMatch}</span>
                        </span>
                      )}
                      {p.contextKeywords.length > 0 && (
                        <span className="flex items-center gap-1 flex-wrap" title="Informational only — not currently used to filter matches">
                          {p.contextKeywords.map((k) => (
                            <span
                              key={k}
                              className="px-1.5 py-0.5 rounded"
                              style={{ background: 'rgba(59,130,246,0.1)', color: '#93c5fd' }}
                            >
                              {k}
                            </span>
                          ))}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {term && filtered.length === 0 && (
        <div className="card text-center py-12">
          <p className="text-gray-400">No patterns match “{search}”.</p>
        </div>
      )}
    </div>
  );
}
