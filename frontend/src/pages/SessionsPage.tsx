import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Search } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { getCaptureSessions, getSession } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { DetailPanel, Field, StateBlock } from '../components/StateBlock';

const yesNo = (v: boolean | null | undefined) => (v === null || v === undefined ? 'unknown' : v ? 'yes' : 'no');
const short = (id: string) => id.split('~').pop() ?? id;

export const SessionsPage = () => {
  const { activeCaptureId } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const [protocol, setProtocol] = useState('all');
  const [search, setSearch] = useState('');
  const list = useAsync(() => getCaptureSessions(activeCaptureId!), activeCaptureId);
  const detail = useAsync(() => getSession(selectedId!), selectedId);

  const rows = useMemo(() => (list.data ?? []).filter((s) =>
    (protocol === 'all' || s.protocol === protocol) &&
    (!search || `${s.source_ip}:${s.source_port} ${s.dest_ip}:${s.dest_port} ${s.cipher_suite ?? ''} ${s.tls_version ?? ''}`
      .toLowerCase().includes(search.toLowerCase()))), [list.data, protocol, search]);

  if (!activeCaptureId) return <StateBlock empty emptyText="Select a capture to view sessions." />;
  const d = detail.data;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Session Explorer</h2>
        <p className="text-sm text-slate-400 mt-1">Reassembled SMTP / IMAP / POP3 connections and what was observable of their TLS negotiation.</p>
      </div>

      <div className="flex flex-wrap items-center gap-4 bg-slate-900/40 p-4 rounded-lg border border-slate-800">
        <label className="flex items-center gap-3 flex-1 min-w-[240px]">
          <Search size={16} className="text-slate-500" />
          <input type="search" aria-label="Search sessions" placeholder="Search IP, port, cipher, version..." value={search}
            onChange={(e) => setSearch(e.target.value)} className="bg-transparent text-sm text-slate-200 placeholder-slate-500 focus:outline-none w-full" />
        </label>
        <select aria-label="Filter by protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)}
          className="bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded px-3 py-1.5">
          <option value="all">All protocols</option><option value="SMTP">SMTP</option><option value="IMAP">IMAP</option><option value="POP3">POP3</option>
        </select>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`space-y-3 ${selectedId ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={list.data?.length ? 'No sessions match the filters.' : 'No email sessions detected in this capture.'}>
            {rows.map((s) => (
              <button key={s.session_id} type="button" onClick={() => open(s.session_id)} aria-pressed={selectedId === s.session_id}
                aria-label={`Open details for session ${s.source_ip}:${s.source_port} to ${s.dest_ip}:${s.dest_port}`}
                className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between gap-4 ${selectedId === s.session_id
                  ? 'bg-slate-800/80 border-amber-500/50' : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'}`}>
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="bg-slate-800 px-2 py-0.5 rounded text-[11px] font-mono font-bold text-amber-400">{s.protocol}</span>
                    {s.implicit_tls && <span className="text-[10px] text-sky-300 border border-sky-800 rounded px-1">implicit TLS</span>}
                    <span className="text-xs text-slate-400 font-mono break-all">{s.source_ip}:{s.source_port} → {s.dest_ip}:{s.dest_port}</span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono break-all">
                    {s.tls_version ? `${s.tls_version} · ${s.cipher_suite ?? 'cipher not observed'}` : s.starttls_state === 'PLAINTEXT' ? 'Plaintext (no TLS observed)' : `${s.starttls_state} · TLS version not observed`}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {s.has_findings && <span className="bg-amber-950 text-amber-300 border border-amber-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">Findings</span>}
                  {s.has_anomaly && <span className="bg-fuchsia-950 text-fuchsia-300 border border-fuchsia-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">ML outlier</span>}
                  {s.has_forward_secrecy === true && <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">PFS</span>}
                  {s.has_forward_secrecy === false && <span className="bg-slate-800 text-slate-300 text-[10px] px-2 py-0.5 rounded font-bold uppercase">No PFS</span>}
                  <ArrowRight size={16} className="text-slate-500" aria-hidden="true" />
                </div>
              </button>
            ))}
          </StateBlock>
        </div>

        {selectedId && (
          <DetailPanel title="Session details" subtitle={short(selectedId)} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error} onRetry={detail.reload}>
              {d && (
                <div className="space-y-4">
                  <div>
                    <Field label="Protocol">{d.protocol}{d.implicit_tls ? ' (implicit TLS)' : ''} · {d.detection_method}</Field>
                    <Field label="Client">{d.source_ip}:{d.source_port}</Field>
                    <Field label="Server">{d.dest_ip}:{d.dest_port}</Field>
                    <Field label="Frames">{d.first_frame} – {d.last_frame} ({d.packet_count} packets, {d.byte_count} B payload)</Field>
                    <Field label="TCP reassembly">{d.reconstruction_quality}</Field>
                    <Field label="STARTTLS">{d.implicit_tls ? 'n/a (implicit TLS)' : d.starttls_state}</Field>
                    <Field label="STARTTLS advertised">{yesNo(d.starttls_advertised)}</Field>
                    <Field label="Negotiated TLS">{d.tls_version ?? 'not observed'}</Field>
                    <Field label="Client offered">{d.detail.tls?.client_max_version ?? 'not observed'}</Field>
                    <Field label="Cipher suite">{d.cipher_suite ?? 'not observed'}</Field>
                    <Field label="Key exchange">{d.key_exchange ?? 'not observed'}{d.key_exchange_group ? ` (${d.key_exchange_group})` : ''}</Field>
                    <Field label="Forward secrecy">{yesNo(d.has_forward_secrecy)}</Field>
                    <Field label="SNI">{d.sni ?? 'not sent'}</Field>
                    <Field label="Handshake">{d.handshake_status ?? 'not observed'}</Field>
                    <Field label="Certificates">{d.certificate_visibility === 'encrypted_tls13' ? 'encrypted (TLS 1.3) — not observable' : `${d.certificates.length} observed`}</Field>
                    {!!d.detail.starttls?.plaintext_auth_mechanisms?.length && (
                      <Field label="Plaintext auth">{d.detail.starttls.plaintext_auth_mechanisms.join(', ')} (values not stored)</Field>
                    )}
                  </div>
                  <div>
                    <span className="text-xs uppercase font-bold text-slate-400 block mb-1">Findings ({d.findings.length})</span>
                    {d.findings.length ? (
                      <ul className="space-y-1">{d.findings.map((f) => (
                        <li key={f}><Link className="text-xs font-mono text-amber-300 hover:underline break-all" to={`/findings?id=${encodeURIComponent(f)}`}>{f.startsWith(`${d.session_id}:`) ? f.slice(d.session_id.length + 1) : f}</Link></li>
                      ))}</ul>
                    ) : <p className="text-xs text-slate-500">None.</p>}
                  </div>
                  {d.certificates.length > 0 && (
                    <div>
                      <span className="text-xs uppercase font-bold text-slate-400 block mb-1">Certificate chain</span>
                      <ul className="space-y-1">{d.certificates.map((c) => (
                        <li key={c}><Link className="text-xs font-mono text-amber-300 hover:underline" to={`/certificates?id=${encodeURIComponent(c)}`}>position {c.split('~c').pop()}</Link></li>
                      ))}</ul>
                    </div>
                  )}
                  {d.anomaly_id !== null && (
                    <Link to={`/anomalies?id=${d.anomaly_id}`} className="text-xs text-fuchsia-300 hover:underline">
                      ML assessment: {d.has_anomaly ? `outlier (${d.anomaly_level})` : 'normal'} →
                    </Link>
                  )}
                </div>
              )}
            </StateBlock>
          </DetailPanel>
        )}
      </div>
    </div>
  );
};
