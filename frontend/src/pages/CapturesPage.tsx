import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { errorMessage, getPolicies, reanalyze } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { fmtScore, fmtUtc } from '../lib/format';

export const CapturesPage = () => {
  const { captures, loading, error, refreshCaptures, setActiveCaptureId, activeCaptureId } = useCapture();
  const policies = useAsync(getPolicies, 'policies');
  const [picked, setPicked] = useState<string[]>([]);
  const [policyFor, setPolicyFor] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const navigate = useNavigate();

  const openAnalysis = (id: string) => { setActiveCaptureId(id); navigate('/'); };
  const toggle = (id: string) => setPicked((p) => p.includes(id) ? p.filter((x) => x !== id) : [...p, id].slice(-2));
  const runReanalysis = async (id: string) => {
    const policy = policyFor[id] ?? 'strict';
    setBusy(id);
    setMsg(null);
    try {
      const r = await reanalyze(id, policy);
      await refreshCaptures();
      setMsg(`Re-analysed with the ${policy} profile as a new analysis.`);
      setActiveCaptureId(r.capture_id);
    } catch (e) {
      setMsg(errorMessage(e, 'Re-analysis failed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures' }]} />
      <PageTitle title="Captures and analysis history"
        lead="Every stored analysis, newest first. Open one to investigate it, re-analyse the same evidence under another policy profile, or select two to compare."
        actions={<>
          <button type="button" className="btn" disabled={picked.length !== 2} onClick={() => navigate(`/compare?a=${picked[0]}&b=${picked[1]}`)}>Compare selected ({picked.length}/2)</button>
          <Link to="/upload" className="btn-primary">Step 2: Analyze a capture</Link>
        </>} />
      {msg && <p role="status" className="notice">{msg}</p>}
      <Panel title={`${captures.length} analysis record(s)`} bodyClass="overflow-x-auto">
        <StateBlock loading={loading && captures.length === 0} error={error} onRetry={() => void refreshCaptures()}
          empty={!loading && captures.length === 0} emptyText="No captures have been analysed yet."
          emptyAction={<Link to="/upload" className="btn-primary">Analyze a capture</Link>}>
          <table className="tbl">
            <thead><tr><th><span className="sr-only">Select for comparison</span></th><th>Capture</th><th>Policy</th><th>Posture</th><th>Contents</th><th>Findings</th><th className="num">ML</th><th>Actions</th></tr></thead>
            <tbody>
              {captures.map((c) => (
                <tr key={c.capture_id} aria-selected={c.capture_id === activeCaptureId}>
                  <td><input type="checkbox" aria-label={`Select ${c.filename} for comparison`} checked={picked.includes(c.capture_id)} onChange={() => toggle(c.capture_id)} disabled={c.analysis_status !== 'completed'} /></td>
                  <td className="min-w-[14rem]">
                    <button type="button" className="link text-left [overflow-wrap:anywhere]" onClick={() => openAnalysis(c.capture_id)}>{c.filename}</button>
                    <div className="text-xs text-ink-3">captured {c.capture_start ? fmtUtc(c.capture_start) : 'n/a'}</div>
                    <div className="text-xs text-ink-3">analysed {fmtUtc(c.analysis_timestamp)} <span className="font-mono">{c.file_hash.slice(0, 12)}</span></div>
                  </td>
                  <td>{c.policy_profile ?? 'balanced'}</td>
                  <td className="whitespace-nowrap">{c.analysis_status === 'completed'
                    ? <><span className="font-semibold tabular-nums">{fmtScore(c.posture_score)}</span> <span className="text-ink-2">{c.posture_status}</span></>
                    : <span className="text-sev-high">{c.analysis_status}{c.analysis_error ? `: ${c.analysis_error}` : ''}</span>}</td>
                  <td className="whitespace-nowrap text-ink-2 tabular-nums">{c.packet_count.toLocaleString()} packets<br />{c.email_session_count} email sessions</td>
                  <td><div className="flex flex-wrap gap-x-3 gap-y-1">{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter((s) => c.severity_counts?.[s]).map((s) => <span key={s} className="inline-flex items-center gap-1"><Severity value={s} compact /><span className="tabular-nums">{c.severity_counts[s]}</span></span>)}{!c.findings_count && <span className="text-ink-3">none</span>}</div></td>
                  <td className="num">{c.anomalies_count}</td>
                  <td>
                    <div className="flex flex-col gap-1.5 items-start">
                      <button type="button" className="btn" onClick={() => openAnalysis(c.capture_id)}>Open</button>
                      {c.analysis_status === 'completed' && <div className="flex items-center gap-1">
                        <select aria-label={`Policy for re-analysing ${c.filename}`} className="field py-1" value={policyFor[c.capture_id] ?? 'strict'}
                          onChange={(e) => setPolicyFor((p) => ({ ...p, [c.capture_id]: e.target.value }))}>
                          {(policies.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </select>
                        <button type="button" className="btn py-1" disabled={busy !== null} onClick={() => void runReanalysis(c.capture_id)}>{busy === c.capture_id ? 'Analysing' : 'Re-analyse'}</button>
                      </div>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </StateBlock>
      </Panel>
    </>
  );
};
