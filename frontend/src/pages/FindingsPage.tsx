import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowRight, Filter, Search } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { errorMessage, getCaptureFindings, getFinding, setFindingStatus } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { SeverityBadge } from '../components/SeverityBadge';
import { DetailPanel, Field, StateBlock } from '../components/StateBlock';
import type { FindingDetail } from '../types/api';

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const STATUSES = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];
const EVIDENCE_LABEL: Record<string, string> = {
  OBSERVED: 'Observed in capture', INFERRED: 'Inferred from observed values',
  POTENTIAL_INDICATOR: 'Potential indicator (not proof)', INSUFFICIENT_EVIDENCE: 'Insufficient evidence',
};

export const FindingsPage = () => {
  const { activeCaptureId } = useCapture();
  const [params, setParams] = useSearchParams();
  const { selectedId, open, close } = useDetailPanel();
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [sort, setSort] = useState<'priority' | 'severity' | 'rule'>('priority');
  const rule = params.get('rule');

  const list = useAsync(() => getCaptureFindings(activeCaptureId!), activeCaptureId);
  const detail = useAsync(() => getFinding(selectedId!), selectedId);
  const [override, setOverride] = useState<FindingDetail | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const shown = override && override.finding_id === selectedId ? override : detail.data;

  const rows = useMemo(() => {
    const q = search.toLowerCase();
    const r = (list.data ?? []).filter((f) =>
      (severity === 'all' || f.severity === severity) && (!rule || f.rule_id === rule) &&
      (!q || f.title.toLowerCase().includes(q) || f.rule_id.toLowerCase().includes(q) || (f.session_id ?? '').toLowerCase().includes(q)));
    const cmp = {
      priority: (a: typeof r[0], b: typeof r[0]) => (a.priority ?? 1e9) - (b.priority ?? 1e9),
      severity: (a: typeof r[0], b: typeof r[0]) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.rule_id.localeCompare(b.rule_id),
      rule: (a: typeof r[0], b: typeof r[0]) => a.rule_id.localeCompare(b.rule_id) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
    }[sort];
    return [...r].sort(cmp);
  }, [list.data, search, severity, rule, sort]);

  const changeStatus = async (status: string) => {
    if (!shown) return;
    setStatusError(null);
    try {
      setOverride(await setFindingStatus(shown.finding_id, status));
      list.reload();
    } catch (e) {
      setStatusError(errorMessage(e, 'Could not update status'));
    }
  };

  if (!activeCaptureId) return <StateBlock empty emptyText="Select a capture to view findings." />;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Security Findings</h2>
        <p className="text-sm text-slate-400 mt-1">Deterministic policy findings. ML anomalies are listed separately and never appear here.</p>
      </div>

      <div className="flex flex-wrap items-center gap-4 bg-slate-900/40 p-4 rounded-lg border border-slate-800">
        <label className="flex items-center gap-3 flex-1 min-w-[240px]">
          <Search size={16} className="text-slate-500" />
          <input type="search" aria-label="Search findings" placeholder="Search by title, rule or session..." value={search}
            onChange={(e) => setSearch(e.target.value)} className="bg-transparent text-sm text-slate-200 placeholder-slate-500 focus:outline-none w-full" />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <Filter size={16} className="text-slate-500" />
          <select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-3 py-1.5">
            <option value="all">All severities</option>
            {Object.keys(SEV_ORDER).map((s) => <option key={s} value={s}>{s[0] + s.slice(1).toLowerCase()}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400">Sort
          <select aria-label="Sort findings" value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}
            className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-3 py-1.5">
            <option value="priority">Priority</option><option value="severity">Severity</option><option value="rule">Rule</option>
          </select>
        </label>
        {rule && (
          <button type="button" onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.delete('rule'); return n; })}
            className="text-xs bg-amber-500/10 border border-amber-600/40 text-amber-300 rounded px-2 py-1">Rule {rule} ✕</button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`space-y-3 ${selectedId ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={list.data?.length ? 'No findings match the filters.' : 'No findings in this capture.'}>
            {rows.map((f) => (
              <button key={f.finding_id} type="button" onClick={() => open(f.finding_id)} aria-label={`Open details for ${f.title}`}
                aria-pressed={selectedId === f.finding_id}
                className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between gap-4 ${selectedId === f.finding_id
                  ? 'bg-slate-800/80 border-amber-500/50' : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'}`}>
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="text-xs font-mono text-slate-500">{f.rule_id}</span>
                    {f.status !== 'open' && <span className="text-[10px] uppercase text-sky-300 border border-sky-700 rounded px-1">{f.status.replace('_', ' ')}</span>}
                  </div>
                  <h4 className="text-sm font-semibold text-slate-200 break-words">{f.title}</h4>
                  <div className="text-[11px] font-mono text-slate-500 truncate">{f.session_id?.split('~').pop()}</div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-xs text-slate-400 font-mono hidden sm:inline">{f.dimension}</span>
                  <ArrowRight size={16} className="text-slate-500" aria-hidden="true" />
                </div>
              </button>
            ))}
          </StateBlock>
        </div>

        {selectedId && (
          <DetailPanel title={shown?.title ?? 'Finding'} subtitle={shown ? `${shown.rule_id} · ${shown.finding_id.split('~').pop()}` : selectedId} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error} onRetry={detail.reload}>
              {shown && (
                <div className="space-y-4 text-sm">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={shown.severity} />
                    <span className="text-xs text-slate-400">{EVIDENCE_LABEL[shown.evidence_type ?? ''] ?? shown.evidence_type}</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed">{shown.explanation}</p>
                  <div>
                    <Field label="Category" mono={false}>{shown.category}</Field>
                    <Field label="Confidence">{Math.round(shown.confidence * 100)}%</Field>
                    <Field label="Score impact (root cause)">{shown.risk_contribution.toFixed(1)} pts</Field>
                    <Field label="Evidence frames">{shown.evidence_frames.length ? shown.evidence_frames.join(', ') : 'not recorded'}</Field>
                    <Field label="Session">
                      {shown.session_id ? <Link className="text-amber-300 hover:underline" to={`/sessions?id=${encodeURIComponent(shown.session_id)}`}>{shown.session_id.split('~').pop()}</Link> : 'none'}
                    </Field>
                  </div>
                  <div>
                    <span className="text-xs uppercase font-bold text-slate-400 block mb-1">Evidence</span>
                    <pre className="bg-slate-950 p-3 rounded font-mono text-[11px] text-amber-200/90 border border-slate-800 overflow-x-auto whitespace-pre-wrap break-all">
                      {JSON.stringify(shown.evidence, null, 2)}
                    </pre>
                  </div>
                  <div>
                    <span className="text-xs uppercase font-bold text-slate-400 block mb-1">Recommendation</span>
                    <p className="text-emerald-300/90 leading-relaxed">{shown.recommendation}</p>
                    {shown.references && <p className="text-[11px] text-slate-500 mt-1">References: {shown.references}</p>}
                  </div>
                  <label className="flex items-center justify-between gap-3 text-xs">
                    <span className="text-slate-400 uppercase font-bold">Triage status</span>
                    <select value={shown.status} onChange={(e) => void changeStatus(e.target.value)}
                      className="bg-slate-950 border border-slate-700 text-slate-200 rounded px-2 py-1">
                      {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                    </select>
                  </label>
                  {statusError && <p role="alert" className="text-xs text-red-300">{statusError}</p>}
                  <p className="text-[11px] text-slate-500">Triage status is analyst metadata; it does not change evidence, severity or the posture score.</p>
                </div>
              )}
            </StateBlock>
          </DetailPanel>
        )}
      </div>
    </div>
  );
};
