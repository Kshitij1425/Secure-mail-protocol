import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getCaptureSessions, getCertificateInventory, getSession, getTimeline } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { Breadcrumbs, Drawer, EvidenceTag, KV, Mono, NeedCapture, PageTitle, Panel, StateBlock, TabPanel, Tabs } from '../components/ui';
import { AnalystNotes } from '../components/AnalystNotes';
import { fmtUtc, shortSession } from '../lib/format';

const yn = (v: boolean | null | undefined) => (v === null || v === undefined ? 'unknown' : v ? 'yes' : 'no');

export const SessionsPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const [proto, setProto] = useState('all');
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<'time' | 'findings' | 'tls'>('time');
  const list = useAsync(() => getCaptureSessions(activeCaptureId!), activeCaptureId);
  const detail = useAsync(() => getSession(selectedId!), selectedId);
  const tl = useAsync(() => getTimeline(activeCaptureId!, selectedId!), activeCaptureId && selectedId ? `${activeCaptureId}|${selectedId}` : null);
  const [params, setParams] = useSearchParams();
  const view = params.get('view') === 'servers' ? 'servers' : 'sessions';
  const setView = (v: string) => setParams((p) => { const n = new URLSearchParams(p); n.set('view', v); n.delete('id'); return n; }, { replace: true });
  const inv = useAsync(() => getCertificateInventory(activeCaptureId!), view === 'servers' ? activeCaptureId : null);

  /* Association by server address and port only: not an assertion of ownership or identity. */
  const servers = useMemo(() => {
    const m = new Map<string, { key: string; protocol: string; addr: string; sessions: number; transitions: Set<string>;
      versions: Set<string>; suites: Set<string>; withFindings: number; outliers: number }>();
    for (const x of list.data ?? []) {
      const addr = `${x.dest_ip}:${x.dest_port}`;
      const key = `${x.protocol} ${addr}`;
      const g = m.get(key) ?? { key, protocol: x.protocol, addr, sessions: 0, transitions: new Set<string>(), versions: new Set<string>(),
        suites: new Set<string>(), withFindings: 0, outliers: 0 };
      g.sessions += 1;
      g.transitions.add(x.implicit_tls ? 'implicit TLS' : (x.starttls_state ?? 'unknown').toLowerCase().replace(/_/g, ' '));
      g.versions.add(x.tls_version ?? 'not observed');
      if (x.cipher_suite) g.suites.add(x.cipher_suite);
      g.withFindings += Number(x.has_findings);
      g.outliers += Number(x.has_anomaly);
      m.set(key, g);
    }
    return [...m.values()].sort((a, b) => b.withFindings - a.withFindings || a.key.localeCompare(b.key));
  }, [list.data]);

  const rows = useMemo(() => {
    const r = (list.data ?? []).filter((s) => (proto === 'all' || s.protocol === proto) &&
      (!q || `${s.source_ip}:${s.source_port} ${s.dest_ip}:${s.dest_port} ${s.cipher_suite ?? ''} ${s.tls_version ?? ''}`.toLowerCase().includes(q.toLowerCase())));
    const by = {
      time: (a: typeof r[0], b: typeof r[0]) => (a.start_timestamp ?? '').localeCompare(b.start_timestamp ?? ''),
      findings: (a: typeof r[0], b: typeof r[0]) => Number(b.has_findings) - Number(a.has_findings),
      tls: (a: typeof r[0], b: typeof r[0]) => (a.tls_version ?? 'zz').localeCompare(b.tls_version ?? 'zz'),
    }[sort];
    return [...r].sort(by);
  }, [list.data, proto, q, sort]);

  if (!activeCaptureId) return <NeedCapture />;
  const d = detail.data;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' },
        { label: 'Sessions', to: '/sessions' }, ...(selectedId ? [{ label: shortSession(selectedId) }] : [])]} />
      <PageTitle title="Email sessions" lead="Reassembled SMTP, IMAP and POP3 connections with what was observable of each TLS negotiation." />
      <Tabs label="Session views" value={view} onChange={setView}
        tabs={[{ id: 'sessions', label: `Sessions (${list.data?.length ?? 0})` }, { id: 'servers', label: `Grouped by server (${servers.length})` }]} />
      {view === 'servers' ? (
        <TabPanel id="servers">
          <p className="text-sm text-ink-2">Sessions grouped by server protocol, address and port as seen in this capture. This is an association of observed connections, not an assertion of ownership or identity.</p>
          <Panel title={`${servers.length} server endpoint(s)`} bodyClass="overflow-x-auto">
            <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && servers.length === 0}
              emptyText="No email sessions were found in this capture.">
              <table className="tbl">
                <thead><tr><th className="sno">S. No.</th><th>Server</th><th className="num">Sessions</th><th>Transition</th><th>TLS versions</th><th>Cipher suites</th><th>Server certificates</th><th className="num">With findings</th><th className="num">ML</th></tr></thead>
                <tbody>
                  {servers.map((g, i) => {
                    const certs = (inv.data ?? []).filter((c) => c.servers.includes(g.addr) && c.chain_positions.includes(0));
                    return (
                      <tr key={g.key}>
                        <td className="sno">{i + 1}</td>
                        <td><button type="button" className="link font-mono text-xs text-left" onClick={() => { setQ(g.addr); setProto(g.protocol); setView('sessions'); }}>{g.protocol} {g.addr}</button></td>
                        <td className="num">{g.sessions}</td>
                        <td className="text-ink-2">{[...g.transitions].join(', ')}</td>
                        <td>{[...g.versions].join(', ')}</td>
                        <td className="font-mono text-xs">{[...g.suites].join(', ') || '-'}</td>
                        <td className="text-xs">{inv.loading ? 'loading' : certs.length ? certs.map((c) => <Link key={c.fingerprint_sha256} className="link block break-all" to={`/certificates?id=${c.fingerprint_sha256}`}>{c.common_name ?? c.subject}{c.is_expired ? ' (expired)' : ''}</Link>) : <span className="text-ink-3">none observed</span>}</td>
                        <td className={`num ${g.withFindings ? 'font-semibold' : ''}`}>{g.withFindings}</td>
                        <td className="num">{g.outliers || ''}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </StateBlock>
          </Panel>
        </TabPanel>
      ) : (<>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 min-w-[16rem] flex-1"><span className="label">Search</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Address, port, cipher or version" className="field" /></label>
        <label className="flex flex-col gap-1"><span className="label">Protocol</span>
          <select value={proto} onChange={(e) => setProto(e.target.value)} className="field">
            <option value="all">All</option><option>SMTP</option><option>IMAP</option><option>POP3</option></select></label>
        <label className="flex flex-col gap-1"><span className="label">Sort by</span>
          <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)} className="field">
            <option value="time">Start time</option><option value="findings">Findings first</option><option value="tls">TLS version</option></select></label>
      </div>

      <div className={`grid gap-5 ${selectedId ? 'grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(26rem,34rem)]' : 'grid-cols-1'}`}>
        <Panel title={`${rows.length} session(s)`} bodyClass="overflow-x-auto">
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={list.data?.length ? 'No sessions match these filters.' : 'No email sessions were found in this capture.'}>
            <table className="tbl">
              <thead><tr><th>Client to server</th><th>Protocol</th><th>Transition</th><th>TLS</th><th>Cipher suite</th><th>Findings</th><th>ML</th></tr></thead>
              <tbody>
                {rows.map((s) => (
                  <tr key={s.session_id} className="row-link" aria-selected={selectedId === s.session_id} onClick={() => open(s.session_id)}>
                    <td><button type="button" className="link font-mono text-xs text-left" onClick={(e) => { e.stopPropagation(); open(s.session_id); }}>{s.source_ip}:{s.source_port} to {s.dest_ip}:{s.dest_port}</button></td>
                    <td>{s.protocol}</td>
                    <td className="text-ink-2">{s.implicit_tls ? 'implicit TLS' : s.starttls_state?.toLowerCase().replace(/_/g, ' ')}</td>
                    <td>{s.tls_version ?? <span className="text-ink-3">not observed</span>}</td>
                    <td className="font-mono text-xs">{s.cipher_suite ?? '-'}</td>
                    <td>{s.has_findings ? 'yes' : 'none'}</td>
                    <td>{s.has_anomaly ? <span className="text-ml font-medium">outlier</span> : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </StateBlock>
        </Panel>

        {selectedId && (
          <Drawer title="Session" subtitle={shortSession(selectedId)} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error} onRetry={detail.reload}>
              {d && <>
                <KV rows={[
                  { k: 'Protocol', v: <>{d.protocol}{d.implicit_tls ? ' over implicit TLS' : ''} <span className="text-ink-3">({d.detection_method})</span></> },
                  { k: 'Client', v: <Mono>{d.source_ip}:{d.source_port}</Mono> },
                  { k: 'Server', v: <Mono>{d.dest_ip}:{d.dest_port}</Mono> },
                  { k: 'Observed', v: <>{fmtUtc(d.start_timestamp, true)} to {fmtUtc(d.end_timestamp, true)}</> },
                  { k: 'Frames', v: <>{d.first_frame}-{d.last_frame} ({d.packet_count} packets, {d.byte_count} payload bytes)</> },
                  { k: 'TCP reassembly', v: d.reconstruction_quality },
                  { k: 'STARTTLS', v: d.implicit_tls ? 'not applicable (implicit TLS)' : `${d.starttls_state}; advertised by server: ${yn(d.starttls_advertised)}` },
                  { k: 'Negotiated TLS', v: d.tls_version ?? <EvidenceTag value="NOT_OBSERVED" /> },
                  { k: 'Client offered', v: d.detail.tls?.client_max_version ?? 'not observed' },
                  { k: 'Cipher suite', v: d.cipher_suite ? <Mono>{d.cipher_suite}</Mono> : 'not observed' },
                  { k: 'Key exchange', v: `${d.key_exchange ?? 'not observed'}${d.key_exchange_group ? ` (${d.key_exchange_group})` : ''}` },
                  { k: 'Forward secrecy', v: yn(d.has_forward_secrecy) },
                  { k: 'SNI', v: d.sni ?? 'not sent' },
                  { k: 'Handshake', v: d.handshake_status ?? 'not observed' },
                  { k: 'Certificates', v: d.certificate_visibility === 'encrypted_tls13' ? <EvidenceTag value="NOT_OBSERVABLE" /> : `${d.certificates.length} observed` },
                  ...(d.detail.starttls?.plaintext_auth_mechanisms?.length ? [{ k: 'Plaintext authentication', v: `${d.detail.starttls.plaintext_auth_mechanisms.join(', ')} (values not stored)` }] : []),
                ]} />
                <section className="space-y-1.5">
                  <h3 className="text-sm font-semibold">Findings ({d.findings.length})</h3>
                  {d.findings.length ? <ul className="space-y-1">{d.findings.map((f) => <li key={f}><Link to={`/findings?id=${encodeURIComponent(f)}`} className="link font-mono text-xs break-all">{f.startsWith(`${d.session_id}:`) ? f.slice(d.session_id.length + 1) : f}</Link></li>)}</ul>
                    : <p className="text-sm text-ink-2">None.</p>}
                </section>
                {d.certificates.length > 0 && (
                  <section className="space-y-1.5">
                    <h3 className="text-sm font-semibold">Certificate chain as presented</h3>
                    <ol className="space-y-1">{d.certificates.map((c) => <li key={c}><Link to={`/certificates?id=${encodeURIComponent(c)}`} className="link text-sm">Position {c.split('~c').pop()}</Link></li>)}</ol>
                  </section>
                )}
                {d.anomaly_id !== null && (
                  <p className="text-sm"><Link to={`/anomalies?id=${d.anomaly_id}`} className="link">ML assessment: {d.has_anomaly ? `outlier (${d.anomaly_level}), requires investigation` : 'consistent with the capture population'}</Link></p>
                )}
                <p className="text-sm"><Link to="/evidence" className="link">Evidence register for this capture</Link></p>
                <section className="space-y-1.5">
                  <h3 className="text-sm font-semibold">Session timeline</h3>
                  <StateBlock loading={tl.loading} error={tl.error}>
                    <ol className="space-y-1 text-sm">
                      {(tl.data ?? []).map((e, i) => (
                        <li key={i} className="grid grid-cols-[auto_1fr] gap-x-3">
                          <span className="text-xs text-ink-3 tabular-nums">{e.ts ? fmtUtc(e.ts, true).slice(11) : 'analysis'}{e.frame ? ` #${e.frame}` : ''}</span>
                          <span>{e.label} <EvidenceTag value={e.evidence_class} /></span>
                        </li>
                      ))}
                    </ol>
                  </StateBlock>
                </section>
                <AnalystNotes captureId={activeCaptureId} targetType="session" targetId={d.session_id} />
              </>}
            </StateBlock>
          </Drawer>
        )}
      </div>
      </>)}
    </>
  );
};
