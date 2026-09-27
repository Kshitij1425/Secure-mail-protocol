import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getTimeline } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, EvidenceTag, NeedCapture, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { fmtUtc, shortSession } from '../lib/format';

const TYPES: Record<string, string> = {
  tcp_open: 'TCP connection', protocol_identified: 'Protocol identified', starttls_command: 'STARTTLS request',
  starttls_response: 'STARTTLS response', plaintext_auth: 'Plaintext authentication', client_hello: 'ClientHello',
  server_hello: 'ServerHello', certificate: 'Certificate', tls_alert: 'TLS alert', handshake_complete: 'Handshake complete',
  tcp_close: 'Connection closed', finding: 'Finding', ml_assessment: 'ML assessment',
};

export const TimelinePage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const [session, setSession] = useState('all');
  const [kind, setKind] = useState('all');
  const tl = useAsync(() => getTimeline(activeCaptureId!), activeCaptureId);
  const sessions = useMemo(() => [...new Set((tl.data ?? []).map((e) => e.session_id))], [tl.data]);
  const rows = (tl.data ?? []).filter((e) => (session === 'all' || e.session_id === session) && (kind === 'all' || e.type === kind));
  if (!activeCaptureId) return <NeedCapture />;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' }, { label: 'Timeline' }]} />
      <PageTitle title="Capture timeline"
        lead="Events reconstructed from the capture, in capture time (UTC) with frame numbers. Findings are placed at the frame that evidences them. ML assessments happen at analysis time and are listed after capture events." />
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
    </>
  );
};
