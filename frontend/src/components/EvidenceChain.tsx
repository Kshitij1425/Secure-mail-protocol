import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { EvidenceChain as Chain } from '../types/api';
import { EvidenceTag, Mono, Severity } from './ui';
import { fmtUtc, shortSession } from '../lib/format';

/**
 * The evidence chain: finding -> session -> TCP stream -> TLS -> certificate -> evidence -> recommendation.
 * Every link states whether it was observed, inferred, or not observable, and links to its detail view.
 */
const Link_ = ({ step, title, status, to, children }: {
  step: string; title: string; status: string; to?: string; children: ReactNode;
}) => (
  <li className="relative pl-8 pb-5 last:pb-0">
    <span aria-hidden="true" className="absolute left-[11px] top-6 bottom-0 w-px bg-line-strong" />
    <span aria-hidden="true" className="absolute left-0 top-0.5 w-6 h-6 rounded-full border border-line-strong bg-panel text-[11px] flex items-center justify-center text-ink-2 font-medium">{step}</span>
    <div className="flex flex-wrap items-center gap-2">
      <h3 className="text-sm font-semibold">{title}</h3>
      <EvidenceTag value={status} />
      {to && <Link to={to} className="link text-xs">Open</Link>}
    </div>
    <div className="mt-1.5 text-sm text-ink-2 space-y-1">{children}</div>
  </li>
);

export const EvidenceChainView = ({ chain }: { chain: Chain }) => {
  const s = chain.session;
  const t = chain.tls;
  const c = chain.certificate;
  const ev = chain.evidence;
  return (
    <ol aria-label="Evidence chain">
      <Link_ step="1" title="Finding" status={chain.finding.evidence_type}>
        <div className="flex flex-wrap items-center gap-2"><Severity value={chain.finding.severity} /><Mono>{chain.finding.rule_id}</Mono></div>
        <p className="text-ink">{chain.finding.description}</p>
      </Link_>
      <Link_ step="2" title="Email session" status={s ? 'OBSERVED' : 'NOT_OBSERVED'} to={s ? `/sessions?id=${encodeURIComponent(s.session_id)}` : undefined}>
        {s ? <>
          <div>{s.protocol}{s.implicit_tls ? ' over implicit TLS' : `, STARTTLS state ${s.starttls_state}`}; identified by {s.detection.method}</div>
          <div><Mono>{s.client.ip}:{s.client.port}</Mono> to <Mono>{s.server.ip}:{s.server.port}</Mono>, started {fmtUtc(s.start_time)}</div>
        </> : <p>Not associated with a session.</p>}
      </Link_>
      <Link_ step="3" title="TCP stream" status={chain.tcp_stream ? 'OBSERVED' : 'NOT_OBSERVED'}>
        {chain.tcp_stream ? <div><Mono>{shortSession(chain.tcp_stream.stream_id)}</Mono>, frames {chain.tcp_stream.first_frame}-{chain.tcp_stream.last_frame}, reassembly {chain.tcp_stream.quality}</div> : <p>Not available.</p>}
      </Link_>
      <Link_ step="4" title="TLS session" status={t.status}>
        {t.status === 'NOT_OBSERVED' ? <p>{t.reason}</p> : <>
          <div>{t.negotiated_version ?? 'version not observed'} with <Mono>{t.cipher_suite ?? 'suite not observed'}</Mono></div>
          <div>Key exchange {t.key_exchange ?? 'not observed'}{t.key_exchange_group ? ` (${t.key_exchange_group})` : ''}; forward secrecy {t.forward_secrecy === null || t.forward_secrecy === undefined ? 'unknown' : t.forward_secrecy ? 'yes' : 'no'}; handshake {t.handshake_status}</div>
          {t.sni && <div>SNI <Mono>{t.sni}</Mono></div>}
        </>}
      </Link_>
      <Link_ step="5" title="Certificate" status={c.status} to={c.certificate_id ? `/certificates?id=${encodeURIComponent(c.certificate_id)}` : undefined}>
        {c.status === 'OBSERVED' ? <>
          <div className="text-ink break-words">{c.subject}</div>
          <div>Serial <Mono>{c.serial_number}</Mono></div>
          <div>SHA-256 <Mono>{c.fingerprint_sha256}</Mono></div>
          <div>Valid {fmtUtc(c.not_before)} to {fmtUtc(c.not_after)}{c.is_expired ? ' (expired at capture time)' : ''}</div>
          <div className="flex items-center gap-2">Trust <EvidenceTag value="NOT_EVALUATED" /><span className="text-xs">no trust anchors are used</span></div>
        </> : <p>{c.reason}</p>}
      </Link_>
      <Link_ step="6" title="Evidence" status={ev.class}>
        <div>Capture frames {ev.frames.length ? ev.frames.join(', ') : 'not recorded'}</div>
        {ev.events.length > 0 && (
          <ul className="space-y-0.5">
            {ev.events.map((e, i) => <li key={i}><span className="text-ink-3">{fmtUtc(e.ts, true)}</span> {e.label}</li>)}
          </ul>
        )}
        <pre className="mt-1 bg-sunken border border-line rounded p-2 text-xs font-mono whitespace-pre-wrap break-all text-ink">{JSON.stringify(ev.values, null, 2)}</pre>
      </Link_>
      <Link_ step="7" title="Recommendation" status="INFERRED">
        <p className="text-ink">{chain.recommendation.action}</p>
        {chain.recommendation.why_it_matters && <p><span className="text-ink-3">Why it matters: </span>{chain.recommendation.why_it_matters}</p>}
        {chain.recommendation.expected_effect && <p><span className="text-ink-3">Expected effect: </span>{chain.recommendation.expected_effect}</p>}
        <p className="text-xs text-ink-3">References: {chain.recommendation.references}</p>
      </Link_>
    </ol>
  );
};
