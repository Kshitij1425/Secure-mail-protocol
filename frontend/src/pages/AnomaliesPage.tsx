import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Sparkles } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { getAnomaly, getCapture, getCaptureAnomalies } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { DetailPanel, Field, StateBlock } from '../components/StateBlock';

const LEVEL_CLS: Record<string, string> = {
  severe: 'bg-red-950 text-red-300 border-red-800', moderate: 'bg-amber-950 text-amber-300 border-amber-800',
  mild: 'bg-yellow-950 text-yellow-300 border-yellow-800', normal: 'bg-slate-800 text-slate-300 border-slate-700',
};

export const AnomaliesPage = () => {
  const { activeCaptureId } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const [showAll, setShowAll] = useState(false);
  const cap = useAsync(() => getCapture(activeCaptureId!), activeCaptureId);
  const list = useAsync(() => getCaptureAnomalies(activeCaptureId!), activeCaptureId);
  const detail = useAsync(() => getAnomaly(Number(selectedId)), selectedId && /^\d+$/.test(selectedId) ? selectedId : null);
  if (!activeCaptureId) return <StateBlock empty emptyText="Select a capture to view ML results." />;

  const rows = (list.data ?? []).filter((a) => showAll || a.is_anomaly);
  const d = detail.data;
  const mlStatus = cap.data?.ml_status;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Sparkles className="text-amber-400" size={24} /> ML Anomaly Detection
          </h2>
          <p className="text-sm text-slate-400 mt-1">Unsupervised Isolation Forest fitted on this capture's own TLS sessions.</p>
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show all evaluated sessions
        </label>
      </div>

      <div className="bg-amber-950/20 border border-amber-800/40 rounded-lg p-4 text-xs text-amber-200/90 leading-relaxed">
        <strong>Supplementary only.</strong> An anomaly is a statistical outlier relative to the other sessions in this capture, not a confirmed
        vulnerability or compromise. ML results never change deterministic findings or the posture score.
        {mlStatus && <> Model status: <span className="font-mono">{mlStatus}</span>.</>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`space-y-3 ${selectedId ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={mlStatus?.startsWith('insufficient') ? 'Too few TLS sessions in this capture for meaningful anomaly detection.'
              : list.data?.length ? 'No sessions flagged as outliers.' : 'No sessions were evaluated by the ML stage.'}>
            {rows.map((a) => (
              <button key={a.id} type="button" onClick={() => open(a.id)} aria-pressed={selectedId === String(a.id)}
                aria-label={`Open ML details for session ${a.session_id.split('~').pop()}`}
                className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between gap-4 ${selectedId === String(a.id)
                  ? 'bg-slate-800/80 border-amber-500/50' : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'}`}>
                <div className="space-y-1 min-w-0">
                  <div className="text-xs font-mono text-slate-400 break-all">{a.session_id.split('~').pop()}</div>
                  <div className="text-sm font-semibold text-slate-200">Anomaly score {a.anomaly_score?.toFixed(3) ?? 'n/a'} <span className="text-slate-500 font-normal text-xs">(negative = outlier)</span></div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border ${LEVEL_CLS[a.anomaly_level ?? 'normal'] ?? LEVEL_CLS.normal}`}>{a.anomaly_level}</span>
                  <ArrowRight size={16} className="text-slate-500" aria-hidden="true" />
                </div>
              </button>
            ))}
          </StateBlock>
        </div>

        {selectedId && (
          <DetailPanel title="Isolation Forest assessment" subtitle={d ? d.session_id.split('~').pop() : selectedId} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error ?? (!/^\d+$/.test(selectedId) ? 'Invalid anomaly id' : null)} onRetry={detail.reload}>
              {d && (
                <div className="space-y-4 text-sm">
                  <p className="text-slate-300 text-xs leading-relaxed">{d.explanation}</p>
                  <div>
                    <Field label="Result">{d.is_anomaly ? `outlier (${d.anomaly_level})` : 'normal'}</Field>
                    <Field label="Score">{d.anomaly_score}</Field>
                    <Field label="Model">{d.model_version}</Field>
                    <Field label="Classification" mono={false}>{d.classification}</Field>
                    <Field label="Session"><Link to={`/sessions?id=${encodeURIComponent(d.session_id)}`} className="text-amber-300 hover:underline">open session</Link></Field>
                  </div>
                  <div>
                    <span className="text-xs uppercase font-bold text-slate-400 block mb-2">Feature vector (10 features)</span>
                    <div className="bg-slate-950 p-3 rounded font-mono text-xs space-y-1 border border-slate-800 text-slate-300">
                      {Object.entries(d.features).filter(([k]) => k !== 'protocol').map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-3"><span className="text-slate-500">{k}</span><span>{typeof v === 'number' ? v.toFixed(2) : String(v)}</span></div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </StateBlock>
          </DetailPanel>
        )}
      </div>
    </div>
  );
};
