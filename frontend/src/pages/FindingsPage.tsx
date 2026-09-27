import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { errorMessage, getCaptureFindings, getFinding, getFindingChain, setFindingStatus } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { EvidenceChainView } from '../components/EvidenceChain';
import { AnalystNotes } from '../components/AnalystNotes';
import { Breadcrumbs, Disclosure, Drawer, EvidenceTag, Mono, NeedCapture, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { sessionEndpoints, severityRank, shortSession } from '../lib/format';
import type { FindingDetail } from '../types/api';

const STATUSES = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];
const HOW: Record<string, string> = {
  OBSERVED: 'Observed: the values are directly visible in the capture bytes.',
  INFERRED: 'Inferred: derived from observed values (for example from the negotiated cipher suite).',
  POTENTIAL_INDICATOR: 'Potential indicator: consistent with an attack or a misconfiguration; the capture cannot tell which.',
  INSUFFICIENT_EVIDENCE: 'Insufficient evidence: the capture does not contain enough data to confirm it.',
};

export const FindingsPage = () => {
  const { activeCaptureId, activeCapture, refreshCaptures } = useCapture();
  const [params, setParams] = useSearchParams();
  const { selectedId, open, close } = useDetailPanel();
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('all');
  const [evidence, setEvidence] = useState('all');
  const [sort, setSort] = useState<'priority' | 'severity' | 'rule' | 'asset'>('priority');
  const rule = params.get('rule');

  const list = useAsync(() => getCaptureFindings(activeCaptureId!), activeCaptureId);
  const chain = useAsync(() => getFindingChain(selectedId!), selectedId);
  const detail = useAsync(() => getFinding(selectedId!), selectedId);
  const [override, setOverride] = useState<FindingDetail | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const d = override?.finding_id === selectedId ? override : detail.data;

  const rows = useMemo(() => {
    const needle = q.toLowerCase();
    const r = (list.data ?? []).filter((f) => (sev === 'all' || f.severity === sev) && (!rule || f.rule_id === rule)
      && (evidence === 'all' || f.evidence_type === evidence)
      && (!needle || `${f.title} ${f.rule_id} ${f.session_id}`.toLowerCase().includes(needle)));
    const by = {
      priority: (a: typeof r[0], b: typeof r[0]) => (a.priority ?? 1e9) - (b.priority ?? 1e9),
      severity: (a: typeof r[0], b: typeof r[0]) => severityRank(a.severity) - severityRank(b.severity) || a.rule_id.localeCompare(b.rule_id),
      rule: (a: typeof r[0], b: typeof r[0]) => a.rule_id.localeCompare(b.rule_id),
      asset: (a: typeof r[0], b: typeof r[0]) => shortSession(a.session_id).localeCompare(shortSession(b.session_id)),
    }[sort];
    return [...r].sort(by);
  }, [list.data, q, sev, evidence, rule, sort]);

  const changeStatus = async (status: string) => {
    if (!d) return;
    setStatusErr(null);
    try {
      setOverride(await setFindingStatus(d.finding_id, status));
      list.reload();
      void refreshCaptures();
    } catch (e) {
      setStatusErr(errorMessage(e, 'Could not update the triage status'));
    }
  };

  if (!activeCaptureId) return <NeedCapture />;
  const ch = chain.data;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' },
        { label: 'Findings', to: '/findings' }, ...(ch ? [{ label: ch.finding.rule_id }] : [])]} />
      <PageTitle title="Findings" lead="Deterministic rule results. Each finding links to the session, TLS negotiation, certificate and capture frames that produced it. ML outliers are listed separately under Anomalies." />

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 min-w-[16rem] flex-1"><span className="label">Search</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Title, rule or session" className="field" /></label>
        <label className="flex flex-col gap-1"><span className="label">Severity</span>
          <select value={sev} onChange={(e) => setSev(e.target.value)} className="field">
            <option value="all">All</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s} value={s}>{s[0] + s.slice(1).toLowerCase()}</option>)}
          </select></label>
        <label className="flex flex-col gap-1"><span className="label">Evidence class</span>
          <select value={evidence} onChange={(e) => setEvidence(e.target.value)} className="field">
            <option value="all">All</option><option value="OBSERVED">Observed</option><option value="INFERRED">Inferred</option>
            <option value="POTENTIAL_INDICATOR">Potential indicator</option><option value="INSUFFICIENT_EVIDENCE">Insufficient evidence</option>
          </select></label>
        <label className="flex flex-col gap-1"><span className="label">Sort by</span>
          <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} className="field">
            <option value="priority">Priority</option><option value="severity">Severity</option><option value="rule">Rule</option><option value="asset">Session</option>
          </select></label>
        {rule && <button type="button" className="btn" onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.delete('rule'); return n; })}>Clear rule filter {rule}</button>}
      </div>

      <div className={`grid gap-5 ${selectedId ? 'grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(26rem,34rem)]' : 'grid-cols-1'}`}>
        <Panel title={`${rows.length} finding(s)`} bodyClass="overflow-x-auto">
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={list.data?.length ? 'No findings match these filters.' : 'This analysis produced no findings.'}>
            <table className="tbl">
              <thead><tr><th className="sno">S. No.</th><th>Severity</th><th>Finding</th><th>Server (client)</th><th>Evidence</th><th>Triage</th></tr></thead>
              <tbody>
                {rows.map((f, i) => (
                  <tr key={f.finding_id} className="row-link" aria-selected={selectedId === f.finding_id}
                    onClick={() => open(f.finding_id)}>
                    <td className="sno">{i + 1}</td>
                    <td><Severity value={f.severity} /></td>
                    <td>
                      <button type="button" className="text-left link" onClick={(e) => { e.stopPropagation(); open(f.finding_id); }}>{f.title}</button>
                      <div className="text-xs text-ink-3 font-mono">{f.rule_id}</div>
                    </td>
                    <td className="font-mono text-xs whitespace-nowrap">{(() => { const e = sessionEndpoints(f.session_id); return e ? <>{e.server}<div className="text-ink-3">{e.client}</div></> : shortSession(f.session_id); })()}</td>
                    <td><EvidenceTag value={f.evidence_type} /></td>
                    <td className="text-ink-2">{f.status.replace('_', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </StateBlock>
        </Panel>

        {selectedId && (
          <Drawer title={ch?.finding.title ?? 'Finding'} subtitle={ch?.finding.rule_id} onClose={close}>
            <StateBlock loading={chain.loading} error={chain.error} onRetry={chain.reload}>
              {ch && d && <>
                <section aria-labelledby="why-h" className="space-y-2">
                  <h3 id="why-h" className="text-sm font-semibold">Why am I seeing this?</h3>
                  <dl className="kv">
                    <dt>What was observed</dt><dd>{ch.finding.description}</dd>
                    <dt>How it was established</dt><dd><EvidenceTag value={ch.finding.evidence_type} /> <span className="text-ink-2">{HOW[ch.finding.evidence_type] ?? ''}</span></dd>
                    <dt>Evidence</dt><dd>Capture frame{ch.evidence.frames.length === 1 ? '' : 's'} {ch.evidence.frames.join(', ') || 'not recorded'} <Link to="/evidence" className="link text-xs">Evidence register</Link></dd>
                    <dt>Affected session</dt><dd>{d.affected_sessions.map((s) => <Link key={s} to={`/sessions?id=${encodeURIComponent(s)}`} className="link font-mono text-xs block break-all">{shortSession(s)}</Link>)}</dd>
                    <dt>TLS</dt><dd>{ch.tls.status === 'NOT_OBSERVED' ? <span className="text-ink-2">{ch.tls.reason}</span> : <>{ch.tls.negotiated_version ?? 'version not observed'} <Mono>{ch.tls.cipher_suite ?? ''}</Mono></>}</dd>
                    <dt>Certificate</dt><dd>{ch.certificate.status === 'OBSERVED' && ch.certificate.certificate_id
                      ? <Link to={`/certificates?id=${encodeURIComponent(ch.certificate.certificate_id)}`} className="link break-words">{ch.certificate.subject}</Link>
                      : <span className="inline-flex flex-wrap items-center gap-2"><EvidenceTag value={ch.certificate.status} /><span className="text-ink-2">{ch.certificate.reason}</span></span>}</dd>
                    <dt>Why it matters</dt><dd>{d.why_it_matters ?? 'not documented'}</dd>
                    <dt>Recommendation</dt><dd>{d.recommendation}</dd>
                    <dt>Expected effect</dt><dd>{d.expected_effect ?? 'not documented'}</dd>
                  </dl>
                  <p className="text-xs text-ink-3">Policy {ch.policy_profile}; confidence {Math.round(ch.finding.confidence * 100)}%; this root cause lowers the score by {ch.finding.risk_contribution.toFixed(1)} points. This is a deterministic rule result, not an ML assessment.</p>
                </section>
                <Disclosure summary="Evidence chain: capture to finding, step by step" open>
                  <EvidenceChainView chain={ch} />
                </Disclosure>
                <AnalystNotes captureId={activeCaptureId} targetType="finding" targetId={ch.finding.finding_id} />
                <section className="space-y-1.5">
                  <label className="flex items-center justify-between gap-3 text-sm">
                    <span className="font-semibold">Triage status</span>
                    <select value={d.status} onChange={(e) => void changeStatus(e.target.value)} className="field">
                      {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
                    </select>
                  </label>
                  {statusErr && <p role="alert" className="text-sm text-sev-high">{statusErr}</p>}
                  <p className="text-xs text-ink-3">Triage is analyst metadata. It does not change evidence, severity or the posture score.</p>
                  <p className="text-xs text-ink-3">Finding ID <Mono>{ch.finding.finding_id}</Mono></p>
                </section>
              </>}
            </StateBlock>
          </Drawer>
        )}
      </div>
    </>
  );
};
