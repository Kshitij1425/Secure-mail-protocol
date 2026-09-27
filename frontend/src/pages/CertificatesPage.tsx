import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getCaptureFindings, getCertificateInventory } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { Breadcrumbs, Drawer, EvidenceTag, KV, Mono, NeedCapture, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { AnalystNotes } from '../components/AnalystNotes';
import { fmtUtc, shortSession } from '../lib/format';
import type { CertificateInventoryItem } from '../types/api';

const validity = (c: CertificateInventoryItem) =>
  c.is_expired ? 'Expired at capture time' : c.is_not_yet_valid ? 'Not yet valid at capture time'
    : c.days_to_expiry_at_capture !== null ? `Valid; ${c.days_to_expiry_at_capture} days remaining at capture time` : 'Valid at capture time';

const LINKAGE: Record<string, string> = {
  verified: 'Signed by the next certificate in the presented chain (signature verified)',
  none: 'Last certificate presented; no issuer in the chain to verify against',
  name_mismatch: 'Issuer name does not match the next certificate',
  signature_invalid: 'Signature does not verify with the next certificate',
  unsupported: 'Signature algorithm could not be verified',
};

export const CertificatesPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const [filter, setFilter] = useState('all');
  const inv = useAsync(() => getCertificateInventory(activeCaptureId!), activeCaptureId);
  const findings = useAsync(() => getCaptureFindings(activeCaptureId!), activeCaptureId);

  const rows = useMemo(() => (inv.data ?? []).filter((c) =>
    filter === 'all' || (filter === 'issues' && (c.is_expired || c.is_not_yet_valid || c.weak_key || c.weak_signature || c.is_self_signed))
    || (filter === 'leaf' && c.chain_positions.includes(0))), [inv.data, filter]);
  const sel = (inv.data ?? []).find((c) => c.fingerprint_sha256 === selectedId || c.certificate_ids.includes(selectedId ?? ''));
  const related = (findings.data ?? []).filter((f) => !!f.session_id && !!sel?.session_ids.includes(f.session_id) && f.rule_id.startsWith('CERT-'));

  if (!activeCaptureId) return <NeedCapture />;
  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' },
        { label: 'Certificates', to: '/certificates' }, ...(sel ? [{ label: sel.common_name ?? 'Certificate' }] : [])]} />
      <PageTitle title="Certificate intelligence"
        lead="Distinct certificates extracted from cleartext TLS Certificate messages (TLS 1.2 and earlier). Extraction, chain linkage and trust are separate questions: linkage is verified by signature; trust against a trust anchor is not evaluated. TLS 1.3 certificates are encrypted and cannot be observed." />
      <label className="flex items-center gap-2 text-sm"><span className="label">Show</span>
        <select value={filter} onChange={(e) => setFilter(e.target.value)} className="field">
          <option value="all">All certificates</option><option value="leaf">Server (leaf) certificates</option><option value="issues">Certificates with issues</option>
        </select></label>

      <div className={`grid gap-5 ${sel ? 'grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(26rem,34rem)]' : 'grid-cols-1'}`}>
        <Panel title={`${rows.length} certificate(s)`} bodyClass="overflow-x-auto">
          <StateBlock loading={inv.loading} error={inv.error} onRetry={inv.reload} empty={!inv.loading && rows.length === 0}
            emptyText={inv.data?.length ? 'No certificates match this filter.' : 'No certificates were observable in this capture.'}>
            <table className="tbl">
              <thead><tr><th>Subject</th><th>Role</th><th>Key</th><th>Validity at capture</th><th className="num">Sessions</th><th>Linkage</th></tr></thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.fingerprint_sha256} className="row-link" aria-selected={sel?.fingerprint_sha256 === c.fingerprint_sha256} onClick={() => open(c.fingerprint_sha256)}>
                    <td><button type="button" className="link text-left break-all" onClick={(e) => { e.stopPropagation(); open(c.fingerprint_sha256); }}>{c.common_name ?? c.subject}</button>
                      <div className="text-xs text-ink-3 break-all">issued by {c.issuer}</div></td>
                    <td className="text-ink-2">{c.chain_positions.includes(0) ? 'server' : c.is_ca ? 'CA' : 'chain'}{c.is_self_signed ? ', self-signed' : ''}</td>
                    <td className={c.weak_key ? 'font-medium text-sev-high' : ''}>{c.public_key_algorithm} {c.public_key_size_bits}{c.weak_key ? ' (weak)' : ''}</td>
                    <td className={c.is_expired || c.is_not_yet_valid ? 'font-medium text-sev-high' : ''}>{c.is_expired ? 'expired' : c.is_not_yet_valid ? 'not yet valid' : `${c.days_to_expiry_at_capture ?? '?'} days left`}</td>
                    <td className="num">{c.session_count}</td>
                    <td className="text-ink-2">{c.chain_linkage.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </StateBlock>
        </Panel>

        {sel && (
          <Drawer title={sel.common_name ?? 'Certificate'} subtitle={`SHA-256 ${sel.fingerprint_sha256}`} onClose={close}>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">Status</h3>
              <KV rows={[
                { k: 'Extraction', v: <><EvidenceTag value="OBSERVED" /> {sel.extraction}</> },
                { k: 'Chain linkage', v: <>{sel.chain_linkage.map((l) => <div key={l}>{LINKAGE[l] ?? l}</div>)}</> },
                { k: 'Trust validation', v: <><EvidenceTag value="NOT_EVALUATED" /> {sel.trust_validation}</> },
                { k: 'Validity', v: validity(sel) },
              ]} />
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">Certificate</h3>
              <KV rows={[
                { k: 'Subject', v: sel.subject },
                { k: 'Issuer', v: sel.issuer },
                { k: 'Serial', v: <Mono>{sel.serial_number}</Mono> },
                { k: 'Valid from', v: fmtUtc(sel.not_before) },
                { k: 'Valid until', v: fmtUtc(sel.not_after) },
                { k: 'Public key', v: `${sel.public_key_algorithm} ${sel.public_key_size_bits} bits${sel.weak_key ? ' (below policy minimum)' : ''}` },
                { k: 'Signature', v: `${sel.signature_algorithm}${sel.weak_signature ? ' (weak hash)' : ''}` },
                { k: 'CA certificate', v: sel.is_ca === null ? 'not stated' : sel.is_ca ? 'yes' : 'no' },
                { k: 'Self-signed', v: sel.is_self_signed ? 'yes (verifies with its own key)' : 'no' },
                { k: 'SAN', v: sel.san_list.length ? sel.san_list.join(', ') : 'none' },
                { k: 'SHA-256', v: <Mono>{sel.fingerprint_sha256}</Mono> },
              ]} />
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">Where it was seen</h3>
              <KV rows={[
                { k: 'Servers', v: sel.servers.join(', ') || 'none' },
                { k: 'SNI requested', v: sel.sni_requested.join(', ') || 'none sent' },
                { k: 'Chain positions', v: sel.chain_positions.join(', ') },
              ]} />
              <ul className="space-y-1">{sel.session_ids.map((s) => <li key={s}><Link className="link font-mono text-xs break-all" to={`/sessions?id=${encodeURIComponent(s)}`}>{shortSession(s)}</Link></li>)}</ul>
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-semibold">Certificate findings on these sessions ({related.length})</h3>
              <StateBlock loading={findings.loading} error={findings.error}>
                {related.length ? (
                  <ul className="space-y-1.5">{related.map((f) => (
                    <li key={f.finding_id} className="flex flex-wrap items-center gap-2 text-sm">
                      <Severity value={f.severity} compact /><Link className="link" to={`/findings?id=${encodeURIComponent(f.finding_id)}`}>{f.title}</Link>
                      <span className="font-mono text-xs text-ink-3">{f.rule_id}</span>
                    </li>))}
                  </ul>
                ) : <p className="text-sm text-ink-2">No certificate rule was triggered on these sessions.</p>}
              </StateBlock>
            </section>
            <AnalystNotes captureId={activeCaptureId} targetType="certificate" targetId={sel.fingerprint_sha256} />
          </Drawer>
        )}
      </div>
    </>
  );
};
