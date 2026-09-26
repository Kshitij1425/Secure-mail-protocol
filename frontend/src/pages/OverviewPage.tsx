import { Link } from 'react-router-dom';
import { Activity, AlertOctagon, FileSearch, GitBranch, Lock, ShieldCheck, Wrench } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { getCapture, getCaptureFindings, getPosture } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { PostureScore } from '../components/PostureScore';
import { MetricCard } from '../components/MetricCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { StateBlock } from '../components/StateBlock';
import { ReportExport } from '../components/ReportExport';

const QUALITY_LABEL: Record<string, string> = {
  full: 'Observed', partial: 'Partially observed', not_observed: 'Not observed', insufficient: 'Insufficient', unknown: 'Unknown',
};

export const OverviewPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const completed = activeCapture?.analysis_status === 'completed';
  const key = activeCaptureId && completed ? activeCaptureId : null;
  const cap = useAsync(() => getCapture(activeCaptureId!), activeCaptureId);
  const posture = useAsync(() => getPosture(activeCaptureId!), key);
  const findings = useAsync(() => getCaptureFindings(activeCaptureId!), key);

  if (!activeCaptureId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
        <ShieldCheck size={48} className="text-slate-600 mb-4" />
        <h3 className="text-lg font-semibold text-slate-300">No capture selected</h3>
        <p className="text-sm text-slate-500 max-w-sm mt-1">Upload a PCAP/PCAPNG capture or pick one from the top bar.</p>
        <Link to="/upload" className="mt-6 bg-amber-500 hover:bg-amber-400 text-slate-950 px-4 py-2 rounded-lg font-bold text-sm">
          Upload capture
        </Link>
      </div>
    );
  }

  const c = cap.data;
  const p = posture.data;
  const sev = c?.severity_counts ?? {};

  return (
    <div className="space-y-6">
      <StateBlock loading={cap.loading && !c} error={cap.error} onRetry={cap.reload}>
        {c && (
          <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-lg border border-slate-800">
            <div className="min-w-0">
              <h2 className="text-xl font-extrabold text-slate-100 tracking-tight break-all">{c.filename}</h2>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400 mt-1 font-mono">
                <span title={c.file_hash}>SHA-256 {c.file_hash.slice(0, 16)}…</span>
                <span>Rules v{c.rule_policy_version ?? '—'} · Scoring v{c.scoring_policy_version ?? '—'}</span>
                {c.capture_start && <span>Captured {new Date(c.capture_start).toISOString().replace('.000Z', 'Z')}</span>}
              </div>
            </div>
            <div className="flex flex-wrap gap-2 items-center">
              <Link to="/findings" className="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded text-xs font-semibold text-slate-200">View Findings</Link>
              <Link to="/sessions" className="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded text-xs font-semibold text-slate-200">Inspect Sessions</Link>
              {completed && <ReportExport captureId={c.capture_id} />}
            </div>
          </div>
        )}
      </StateBlock>

      {c && c.analysis_status === 'failed' && (
        <div role="alert" className="bg-red-950/40 border border-red-800 text-red-200 rounded-lg p-4 text-sm">
          Analysis failed: {c.analysis_error || 'unknown error'}. Upload a valid PCAP/PCAPNG capture.
        </div>
      )}

      {c && completed && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 flex flex-col items-center justify-center">
            <span className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-4">Security Posture</span>
            <PostureScore score={c.posture_score} status={c.posture_status || 'Unknown'} />
          </div>
          <div className="md:col-span-3 grid grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard label="Packets" value={c.packet_count.toLocaleString()} sub={`${c.stream_count} TCP streams`} icon={<Activity size={20} />} />
            <MetricCard label="Email Sessions" value={c.email_session_count} sub="SMTP / IMAP / POP3" icon={<Lock size={20} />} />
            <MetricCard label="TLS Observed" value={c.tls_session_count} sub={`${c.certificates_count} certificate(s)`} icon={<ShieldCheck size={20} />} />
            <MetricCard label="ML Anomalies" value={c.anomalies_count} sub={c.ml_status ?? 'supplementary'} icon={<FileSearch size={20} />} />
            <MetricCard label="Critical" value={sev.CRITICAL ?? 0} sub="Immediate action" />
            <MetricCard label="High" value={sev.HIGH ?? 0} sub="High risk" />
            <MetricCard label="Medium" value={sev.MEDIUM ?? 0} sub="Moderate risk" />
            <MetricCard label="Low / Info" value={(sev.LOW ?? 0) + (sev.INFO ?? 0)} sub="Advisory" />
          </div>
        </div>
      )}

      {completed && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 space-y-3">
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2"><GitBranch size={18} className="text-amber-400" />Posture by dimension</h3>
            <StateBlock loading={posture.loading} error={posture.error} onRetry={posture.reload}>
              <table className="w-full text-xs">
                <thead className="text-slate-500 text-left"><tr><th className="py-1">Dimension</th><th>Score</th><th>Findings</th><th>Coverage</th><th>Evidence</th></tr></thead>
                <tbody>
                  {p?.dimension_scores.map((d) => (
                    <tr key={d.dimension} className="border-t border-slate-800/70 text-slate-300">
                      <td className="py-1.5">{d.name}</td>
                      <td className="font-mono">{d.score === null ? 'N/A' : Math.round(d.score)}</td>
                      <td className="font-mono">{d.findings_count}</td>
                      <td className="font-mono">{Math.round(d.coverage_percent)}%</td>
                      <td>{QUALITY_LABEL[d.evidence_quality] ?? d.evidence_quality}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {p && p.overall_score === null && (
                <p className="text-xs text-slate-400 mt-2">No email session with assessable evidence was found. Absence of evidence is reported, not scored.</p>
              )}
            </StateBlock>
          </section>

          <section className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 space-y-3">
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2"><Wrench size={18} className="text-amber-400" />Prioritised remediation</h3>
            <StateBlock loading={posture.loading} error={posture.error} empty={!!p && p.remediation_plan.length === 0} emptyText="No actionable findings.">
              <ol className="space-y-2">
                {p?.remediation_plan.slice(0, 6).map((r) => (
                  <li key={r.rule_id} className="text-xs text-slate-300 flex gap-3">
                    <span className="font-mono text-slate-500 w-4 shrink-0">{r.priority}.</span>
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SeverityBadge severity={r.severity} size="sm" />
                        <Link to={`/findings?rule=${encodeURIComponent(r.rule_id)}`} className="font-semibold text-slate-100 hover:text-amber-300">{r.title}</Link>
                        <span className="text-slate-500">{r.affected_sessions} session(s)</span>
                      </div>
                      <p className="text-emerald-300/90">{r.recommendation}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </StateBlock>
          </section>
        </div>
      )}

      {completed && (
        <section className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
              <AlertOctagon size={18} className="text-amber-400" /> Top findings ({findings.data?.length ?? 0})
            </h3>
            <Link to="/findings" className="text-xs text-amber-400 hover:text-amber-300 font-semibold">View all →</Link>
          </div>
          <StateBlock loading={findings.loading} error={findings.error} onRetry={findings.reload}
            empty={!!findings.data && findings.data.length === 0} emptyText="No security findings in this capture.">
            <div className="divide-y divide-slate-800">
              {findings.data?.slice(0, 5).map((f) => (
                <Link key={f.finding_id} to={`/findings?id=${encodeURIComponent(f.finding_id)}`}
                  className="py-3 flex items-center justify-between gap-4 hover:bg-slate-800/40 px-2 rounded">
                  <span className="flex items-center gap-3 min-w-0">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="text-sm font-medium text-slate-200 truncate">{f.title}</span>
                  </span>
                  <span className="text-xs text-slate-500 font-mono shrink-0">{f.rule_id}</span>
                </Link>
              ))}
            </div>
          </StateBlock>
        </section>
      )}
    </div>
  );
};
