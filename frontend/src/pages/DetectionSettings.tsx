import { useQuery } from '@tanstack/react-query';
import { patternsAPI } from '../lib/api';
import { Mail, FilterX, Calculator, ListTree, Clock, Gauge, Layers } from 'lucide-react';

/**
 * Detection Settings — everything that shapes what becomes a finding but
 * ISN'T tied to any single pattern: the always-on domain pattern, the
 * false-positive suppression rules, and the full criticality scoring model.
 * Read-only, same as Detection Patterns — nothing here is user-configurable.
 */

export default function DetectionSettings() {
  const { data: catalog, isLoading, isError } = useQuery({
    queryKey: ['patterns'],
    queryFn: async () => (await patternsAPI.getAll()).data,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-gray-400 animate-subtle-pulse">Loading detection settings...</div>
      </div>
    );
  }

  if (isError || !catalog) {
    return (
      <div className="card text-center py-12">
        <p className="text-gray-400">Failed to load detection settings.</p>
      </div>
    );
  }

  const model = catalog.criticalityModel;

  return (
    <div className="space-y-6">
      {/* Always-on domain pattern */}
      <div
        className="card flex items-start gap-3"
        style={{ background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.2)' }}
      >
        <Mail className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-bold text-blue-300">Applied to every scan, in addition to every pattern</div>
          <div className="text-sm text-gray-300 mt-0.5">{catalog.domainPattern.description}</div>
          <code
            className="block text-xs mt-2 break-all px-2 py-1 rounded w-fit"
            style={{ fontFamily: 'ui-monospace, SFMono-Regular, monospace', color: 'rgba(148,163,184,0.9)', background: 'rgba(255,255,255,0.03)' }}
          >
            {catalog.domainPattern.template}
          </code>
          <div className="text-xs text-gray-500 mt-1">
            No entropy filter — presence alone is enough (context: {catalog.domainPattern.contextKeywords.join(', ')}).
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* False positive filtering */}
        <div className="card">
          <div className="flex items-center gap-2 mb-1">
            <FilterX className="w-4 h-4 text-amber-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">False-Positive Suppression</div>
          </div>
          <p className="text-xs text-gray-500 mb-3">
            Applied to every match, regardless of type — a match is dropped before it ever becomes a finding.
          </p>
          <div className="space-y-3">
            <div>
              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Text itself looks like a placeholder
              </div>
              <div className="flex flex-wrap gap-1.5">
                {catalog.falsePositiveFilters.contentPatterns.map((p, i) => (
                  <code
                    key={i}
                    className="text-xs px-1.5 py-0.5 rounded break-all"
                    style={{ fontFamily: 'ui-monospace, SFMono-Regular, monospace', color: 'rgba(148,163,184,0.9)', background: 'rgba(255,255,255,0.03)' }}
                  >
                    /{p.source}/{p.flags}
                  </code>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Surrounding context contains
              </div>
              <div className="flex flex-wrap gap-1.5">
                {catalog.falsePositiveFilters.contextSubstrings.map((s) => (
                  <span
                    key={s}
                    className="text-xs px-1.5 py-0.5 rounded font-mono"
                    style={{ background: 'rgba(245,158,11,0.1)', color: '#fbbf24' }}
                  >
                    {s}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-1">
            <Calculator className="w-4 h-4 text-blue-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">Criticality Calculation</div>
          </div>
          <p className="text-xs text-gray-500 mb-4">
            Every finding is scored 0–{model.maxScore}. These four components add up to that score, then map to a
            criticality label.
          </p>
          <div className="space-y-3">
            {model.components.map((c) => (
              <div key={c.key}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-gray-300">{c.label}</span>
                  <span className="text-gray-500">{c.maxPoints} pts</span>
                </div>
                <div className="w-full h-1.5 rounded-full overflow-hidden mb-1" style={{ background: 'rgba(255,255,255,0.06)' }}>
                  <div
                    className="h-full rounded-full bg-blue-500/70"
                    style={{ width: `${(c.maxPoints / model.maxScore) * 100}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500 leading-snug">{c.description}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <ListTree className="w-4 h-4 text-red-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">Context Keyword Rules</div>
          </div>
          <div className="space-y-3 text-xs">
            <div>
              <div className="text-gray-400 mb-1">
                Critical keywords <span className="text-emerald-400 font-semibold">+{model.contextRules.criticalKeywordBonus}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {model.contextRules.criticalKeywords.map((k) => (
                  <span key={k} className="px-1.5 py-0.5 rounded font-mono" style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171' }}>
                    {k}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-gray-400 mb-1">
                High-risk keywords <span className="text-emerald-400 font-semibold">+{model.contextRules.highRiskKeywordBonus}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {model.contextRules.highRiskKeywords.map((k) => (
                  <span key={k} className="px-1.5 py-0.5 rounded font-mono" style={{ background: 'rgba(251,146,60,0.1)', color: '#fb923c' }}>
                    {k}
                  </span>
                ))}
              </div>
            </div>
            <div className="text-gray-500">
              Inside a comment (<code className="font-mono">// /* # """</code>):{' '}
              <span className="text-red-400 font-semibold">-{model.contextRules.commentPenalty}</span>
            </div>
            <div className="text-gray-500">
              Looks like an env var (<code className="font-mono">export X= / process.env</code>):{' '}
              <span className="text-emerald-400 font-semibold">+{model.contextRules.envVarBonus}</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-4 h-4 text-purple-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">Commit Recency</div>
          </div>
          <div className="space-y-1.5 text-xs">
            {model.recencyBrackets.map((b) => (
              <div key={b.label} className="flex items-center justify-between text-gray-400">
                <span>{b.label}</span>
                <span className="text-gray-300 font-semibold">{b.score} pts</span>
              </div>
            ))}
            <div className="flex items-center justify-between text-gray-500 pt-1.5 mt-1.5" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <span>No commit date available</span>
              <span className="text-gray-300 font-semibold">{model.recencyDefaultScore} pts</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <Gauge className="w-4 h-4 text-emerald-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">Score → Criticality</div>
          </div>
          <div className="space-y-1.5 text-xs">
            {model.criticalityThresholds.map((t) => (
              <div key={t.label} className="flex items-center justify-between">
                <span className="text-gray-400">≥ {t.min}</span>
                <span
                  className="px-2 py-0.5 rounded font-bold"
                  style={{
                    background:
                      t.label === 'CRITICAL' ? 'rgba(239,68,68,0.15)' :
                      t.label === 'HIGH' ? 'rgba(251,146,60,0.15)' :
                      t.label === 'MEDIUM' ? 'rgba(250,204,21,0.15)' :
                      t.label === 'LOW' ? 'rgba(148,163,184,0.15)' : 'rgba(100,116,139,0.15)',
                    color:
                      t.label === 'CRITICAL' ? '#f87171' :
                      t.label === 'HIGH' ? '#fb923c' :
                      t.label === 'MEDIUM' ? '#facc15' :
                      t.label === 'LOW' ? '#cbd5e1' : '#94a3b8',
                  }}
                >
                  {t.label}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="w-4 h-4 text-gray-400" />
            <div className="text-sm font-bold text-gray-100 uppercase tracking-wider">Multiple Secrets in One File</div>
          </div>
          <p className="text-xs text-gray-500 leading-snug">{model.fileAggregation.description}</p>
          <div className="text-xs text-gray-400 mt-2">
            High-value threshold: <span className="text-gray-200 font-semibold">≥ {model.fileAggregation.highValueThreshold}</span>
            <br />
            Bonus per extra type: <span className="text-emerald-400 font-semibold">+{model.fileAggregation.bonusPerAdditionalType}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
