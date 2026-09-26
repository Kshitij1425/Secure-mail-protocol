import { Link } from 'react-router-dom';
import { ArrowRight, Receipt } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { getCaptureCertificates, getCertificate } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { DetailPanel, Field, StateBlock } from '../components/StateBlock';
import type { CertificateSummary } from '../types/api';

const validity = (c: CertificateSummary) =>
  c.is_expired ? ['Expired at capture', 'bg-red-950 text-red-300 border-red-800']
    : c.is_not_yet_valid ? ['Not yet valid', 'bg-red-950 text-red-300 border-red-800']
    : ['In validity period', 'bg-emerald-950 text-emerald-300 border-emerald-800'];

export const CertificatesPage = () => {
  const { activeCaptureId } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const list = useAsync(() => getCaptureCertificates(activeCaptureId!), activeCaptureId);
  const detail = useAsync(() => getCertificate(selectedId!), selectedId);
  if (!activeCaptureId) return <StateBlock empty emptyText="Select a capture to view certificates." />;
  const d = detail.data;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Certificate Inventory</h2>
        <p className="text-sm text-slate-400 mt-1">
          X.509 certificates visible in cleartext TLS Certificate messages (TLS ≤ 1.2). TLS 1.3 encrypts certificates, so they cannot be observed passively.
          Trust is not evaluated: no trust-anchor store is consulted.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className={`space-y-3 ${selectedId ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload}
            empty={!!list.data && list.data.length === 0} emptyText="No certificates observed in this capture.">
            {list.data?.map((c) => {
              const [label, cls] = validity(c);
              return (
                <button key={c.certificate_id} type="button" onClick={() => open(c.certificate_id)} aria-pressed={selectedId === c.certificate_id}
                  aria-label={`Open details for certificate ${c.subject ?? c.fingerprint_sha256}`}
                  className={`w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between gap-4 ${selectedId === c.certificate_id
                    ? 'bg-slate-800/80 border-amber-500/50' : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'}`}>
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Receipt size={16} className="text-amber-400 shrink-0" />
                      <span className="text-sm font-semibold text-slate-200 break-all">{c.common_name ?? c.subject}</span>
                      <span className="text-[10px] text-slate-400">{c.chain_position === 0 ? 'leaf' : `chain #${c.chain_position}`}</span>
                    </div>
                    <div className="text-xs text-slate-400 font-mono break-all">Issuer: {c.issuer}</div>
                    <div className="text-[11px] text-slate-500 font-mono">{c.public_key_algorithm} {c.public_key_size_bits ? `${c.public_key_size_bits}-bit` : ''}{c.is_self_signed ? ' · self-signed' : ''}</div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className={`border text-[10px] px-2 py-0.5 rounded font-bold uppercase ${cls}`}>{label}</span>
                    <ArrowRight size={16} className="text-slate-500" aria-hidden="true" />
                  </div>
                </button>
              );
            })}
          </StateBlock>
        </div>

        {selectedId && (
          <DetailPanel title="X.509 certificate" subtitle={d ? `SHA-256 ${d.fingerprint_sha256}` : selectedId} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error} onRetry={detail.reload}>
              {d && (
                <div>
                  <Field label="Subject">{d.subject}</Field>
                  <Field label="Issuer">{d.issuer}</Field>
                  <Field label="Serial">{d.serial_number}</Field>
                  <Field label="Valid from">{d.not_before}</Field>
                  <Field label="Valid until">{d.not_after}</Field>
                  <Field label="Validity evaluated at">{d.validity_reference === 'capture_time' ? 'capture time' : d.validity_reference}</Field>
                  <Field label="Status">{validity(d)[0]}</Field>
                  <Field label="Public key">{d.public_key_algorithm} {d.public_key_size_bits}-bit{d.weak_key ? ' (weak)' : ''}</Field>
                  <Field label="Signature">{d.signature_algorithm}{d.weak_signature ? ' (weak hash)' : ''}</Field>
                  <Field label="CA certificate">{d.is_ca === null ? 'not stated' : d.is_ca ? 'yes' : 'no'}</Field>
                  <Field label="Self-signed">{d.is_self_signed ? 'yes (signature verified with own key)' : 'no'}</Field>
                  <Field label="Signed by next in chain">{d.issued_by_next ?? 'n/a'}</Field>
                  <Field label="Trust">{d.trust_status} — not evaluated (no trust anchors)</Field>
                  <Field label="SAN">{d.san_list.length ? d.san_list.join(', ') : 'none'}</Field>
                  <Field label="Seen in sessions">
                    <span className="flex flex-col items-end gap-1">
                      {d.seen_in_sessions.map((s) => (
                        <Link key={s} to={`/sessions?id=${encodeURIComponent(s)}`} className="text-amber-300 hover:underline">{s.split('~').pop()}</Link>
                      ))}
                    </span>
                  </Field>
                </div>
              )}
            </StateBlock>
          </DetailPanel>
        )}
      </div>
    </div>
  );
};
