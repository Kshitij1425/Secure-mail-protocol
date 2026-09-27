import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getTimeline } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, EvidenceTag, NeedCapture, PageTitle, Panel, Severity, StateBlock, TabPanel, Tabs } from '../components/ui';
import { fmtUtc, sessionEndpoints, shortSession } from '../lib/format';

const TYPES: Record<string, string> = {
  tcp_open: 'TCP connection', protocol_identified: 'Protocol identified', starttls_command: 'STARTTLS request',
  starttls_response: 'STARTTLS response', plaintext_auth: 'Plaintext authentication', client_hello: 'ClientHello',
  server_hello: 'ServerHello', certificate: 'Certificate', tls_alert: 'TLS alert', handshake_complete: 'Handshake complete',
  tcp_close: 'Connection closed', finding: 'Finding', ml_assessment: 'ML assessment',
};

/**
 * Step 7, Evidence: the evidence register (one numbered entry per finding, anchored at the capture
 * frame that evidences it) and the full capture timeline.
 */
export const EvidencePage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const [params, setParams] = useSearchParams();
  const view = params.get('view') === 'timeline' ? 'timeline' : 'register';
  const setView = (v: string) => setParams((p) => { const n = new URLSearchParams(p); n.set('view', v); return n; }, { replace: true });
  const [session, setSession] = useState('all');
  const [kind, setKind] = useState('all');
  const tl = useAsync(() => getTimeline(activeCaptureId!), activeCaptureId);
  const sessions = useMemo(() => [...new Set((tl.data ?? []).map((e) => e.session_id))], [tl.data]);
  const register = useMemo(() => (tl.data ?? []).filter((e) => e.type === 'finding'), [tl.data]);
  const rows = (tl.data ?? []).filter((e) => (session === 'all' || e.session_id === session) && (kind === 'all' || e.type === kind));
  if (!activeCaptureId) return <NeedCapture />;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' }, { label: 'Evidence' }]} />
      <PageTitle title="Evidence"
        lead="What in the capture supports each finding: the capture frame, its capture time and how the fact was established (observed, inferred, not observable). All times are capture time in UTC." />
      <Tabs label="Evidence views" value={view} onChange={setView}
        tabs={[{ id: 'register', label: `Evidence register (${register.length})` }, { id: 'timeline', label: `Capture timeline (${tl.data?.length ?? 0})` }]} />

      {view === 'register' ? (
        <TabPanel id="register">
          <Panel title="Evidence register" bodyClass="overflow-x-auto">
            <StateBlock loading={tl.loading} error={tl.error} onRetry={tl.reload} empty={!tl.loading && register.length === 0}
              emptyText="No findings, so no evidence entries. The capture timeline still lists every observed event.">
              <table className="tbl">
                <thead><tr><th className="sno">S. No.</th><th>Finding</th><th>Evidence class</th><th className="num">Frame</th><th>Capture time (UTC)</th><th>Server (client)</th><th /></tr></thead>
                <tbody>
                  {register.map((e, i) => {
                    const ep = sessionEndpoints(e.session_id);
                    return (
                      <tr key={e.finding_id ?? i}>
                        <td className="sno">{i + 1}</td>
                        <td>{e.severity && <Severity value={e.severity} compact />}<div className="mt-0.5">{e.label}</div></td>
                        <td><EvidenceTag value={e.evidence_class} /></td>
                        <td className="num">{e.frame ?? 'not recorded'}</td>
                        <td className="tabular-nums whitespace-nowrap text-ink-2">{e.ts ? fmtUtc(e.ts, true) : 'analysis time'}</td>
                        <td className="font-mono text-xs whitespace-nowrap"><Link className="link" to={`/sessions?id=${encodeURIComponent(e.session_id)}`}>{ep ? ep.server : shortSession(e.session_id)}</Link>{ep && <div className="text-ink-3">{ep.client}</div>}</td>
                        <td>{e.finding_id && <Link className="link text-sm whitespace-nowrap" to={`/findings?id=${encodeURIComponent(e.finding_id)}`}>Evidence chain</Link>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </StateBlock>
          </Panel>
          <p className="text-xs text-ink-3">Frame numbers are 1-based positions in the original capture file and can be opened in any packet analyser. The capture SHA-256 in the header identifies the exact file.</p>
        </TabPanel>
      ) : (
        <TabPanel id="timeline">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1"><span className="label">Session</span>
              <select value={session} onChange={(e) => setSession(e.target.value)} className="field max-w-[28rem]">
                <option value="all">All sessions ({sessions.length})</option>
                {sessions.map((s) => <option key={s} value={s}>{shortSession(s)}</option>)}
              </select></label>
            <label className="flex flex-col gap-1"><span className="label">Event type</span>
              <select value={kind} onChange={(e) => setKind(e.target.value)} className="field">
                <option value="all">All events</option>
                {Object.entries(TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select></label>
          </div>
          <Panel title={`${rows.length} event(s)`} bodyClass="overflow-x-auto">
            <StateBlock loading={tl.loading} error={tl.error} onRetry={tl.reload} empty={!tl.loading && rows.length === 0}
              emptyText={tl.data?.length ? 'No events match these filters.' : 'No email sessions, so no events.'}>
              <table className="tbl">
                <thead><tr><th>Capture time (UTC)</th><th className="num">Frame</th><th>Event</th><th>Detail</th><th>Class</th><th>Session</th></tr></thead>
                <tbody>
                  {rows.map((e, i) => (
                    <tr key={i}>
                      <td className="tabular-nums whitespace-nowrap text-ink-2">{e.ts ? fmtUtc(e.ts, true) : 'analysis time'}</td>
                      <td className="num">{e.frame ?? ''}</td>
                      <td className="whitespace-nowrap">{TYPES[e.type] ?? e.type}</td>
                      <td>{e.finding_id ? <span className="inline-flex flex-wrap items-center gap-2">{e.severity && <Severity value={e.severity} compact />}<Link className="link" to={`/findings?id=${encodeURIComponent(e.finding_id)}`}>{e.label}</Link></span> : e.label}</td>
                      <td><EvidenceTag value={e.evidence_class} /></td>
                      <td><Link className="link font-mono text-xs" to={`/sessions?id=${encodeURIComponent(e.session_id)}`}>{shortSession(e.session_id)}</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </StateBlock>
          </Panel>
          <p className="text-xs text-ink-3">Findings are placed at the frame that evidences them. ML assessments happen at analysis time and are listed after capture events.</p>
        </TabPanel>
      )}
    </>
  );
};
