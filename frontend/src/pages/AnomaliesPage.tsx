import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getAnomaly, getCapture, getCaptureAnomalies } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { useDetailPanel } from '../hooks/useDetailPanel';
import { Breadcrumbs, Drawer, EvidenceTag, KV, NeedCapture, PageTitle, Panel, StateBlock } from '../components/ui';
import { shortSession } from '../lib/format';

const FEATURE_LABEL: Record<string, string> = {
  protocol_version: 'TLS version (0 = SSL 2.0 ... 4 = TLS 1.2, 5 = TLS 1.3)',
  forward_secrecy: 'Forward secrecy (1 = yes)',
  aead_cipher: 'AEAD cipher (1 = yes)',
  cipher_class: 'Cipher class (0 insecure, 1 weak, 2 legacy, 3 recommended)',
  key_exchange_security_bits: 'Key exchange strength (security bits)',
  certificate_key_security_bits: 'Certificate key strength (security bits)',
  certificate_signature_hash: 'Signature hash (0 MD5, 1 SHA-1, 2 SHA-2+)',
  certificate_valid_at_capture: 'Certificate valid at capture time (1 = yes)',
  certificate_days_to_expiry: 'Days to certificate expiry at capture',
  certificate_not_self_signed: 'Certificate not self-signed (1 = yes)',
};

const fmtFeature = (v: unknown) =>
  v === null || v === undefined ? 'not observable' : typeof v === 'number' ? (Number.isInteger(v) ? String(v) : v.toFixed(2)) : String(v);

export const AnomaliesPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const { selectedId, open, close } = useDetailPanel();
  const [showAll, setShowAll] = useState(false);
  const cap = useAsync(() => getCapture(activeCaptureId!), activeCaptureId);
  const list = useAsync(() => getCaptureAnomalies(activeCaptureId!), activeCaptureId);
  const valid = selectedId && /^\d+$/.test(selectedId) ? selectedId : null;
  const detail = useAsync(() => getAnomaly(Number(valid)), valid);
  if (!activeCaptureId) return <NeedCapture />;

  const rows = (list.data ?? []).filter((a) => showAll || a.is_anomaly);
  const d = detail.data;
  const ml = cap.data?.ml_status;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' }, { label: 'Anomalies' }]} />
      <PageTitle title="ML anomalies"
        lead="An unsupervised Isolation Forest is fitted on this capture's own TLS sessions. Only sessions that are cryptographically weaker than this capture's norm, and rare here, are reported. These are investigation leads, not findings." />
      <div className="notice">
        <strong>Rule-based findings and ML anomalies are separate.</strong> An outlier is a session whose TLS and certificate
        features are weaker than, and unusual relative to, the rest of this capture. A weakness shared by most sessions is not an outlier (the rules still report it). It requires investigation; it is not a confirmed vulnerability or compromise,
        and it never changes findings or the posture score. Model status: <span className="font-mono">{ml ?? 'unknown'}</span>.
      </div>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> Show every evaluated session, not only outliers</label>

      <div className={`grid gap-5 ${d ? 'grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(26rem,34rem)]' : 'grid-cols-1'}`}>
        <Panel title={`${rows.length} session(s)`} bodyClass="overflow-x-auto">
          <StateBlock loading={list.loading} error={list.error} onRetry={list.reload} empty={!list.loading && rows.length === 0}
            emptyText={ml?.startsWith('insufficient') ? 'Too few TLS sessions in this capture for anomaly detection (5 or more are required).'
              : list.data?.length ? 'No session was flagged as an outlier.' : 'No sessions were evaluated by the ML stage.'}>
            <table className="tbl">
              <thead><tr><th>Session</th><th>Result</th><th className="num">Score</th></tr></thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} className="row-link" aria-selected={selectedId === String(a.id)} onClick={() => open(a.id)}>
                    <td><button type="button" className="link font-mono text-xs text-left" onClick={(e) => { e.stopPropagation(); open(a.id); }}>{shortSession(a.session_id)}</button></td>
                    <td>{a.is_anomaly ? <span className="text-ml font-medium">Outlier ({a.anomaly_level}): requires investigation</span> : 'Consistent with population'}</td>
                    <td className="num">{a.anomaly_score?.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-ink-3 px-3 py-2">Score: positive means consistent with the population, negative means outlier (normalised Isolation Forest decision value).</p>
          </StateBlock>
        </Panel>

        {valid && (
          <Drawer title="Isolation Forest assessment" subtitle={d ? shortSession(d.session_id) : valid} onClose={close}>
            <StateBlock loading={detail.loading} error={detail.error} onRetry={detail.reload}>
              {d && <>
                <KV rows={[
                  { k: 'Classification', v: <><EvidenceTag value={d.is_anomaly ? 'ML_ANOMALY' : 'ML_ASSESSMENT'} /> {d.classification}</> },
                  { k: 'Result', v: d.is_anomaly ? `Outlier, ${d.anomaly_level}` : 'Consistent with the capture population' },
                  { k: 'Score', v: d.anomaly_score },
                  { k: 'Model', v: d.model_version },
                  { k: 'TLS session', v: <Link className="link font-mono text-xs break-all" to={`/sessions?id=${encodeURIComponent(d.session_id)}`}>{shortSession(d.session_id)}</Link> },
                ]} />
                <section className="space-y-1.5">
                  <h3 className="text-sm font-semibold">Why this session was assessed this way</h3>
                  <p className="text-sm">{d.explanation}</p>
                </section>
                <section className="space-y-1.5">
                  <h3 className="text-sm font-semibold">Posture features ({Object.keys(d.features).filter((k) => k !== 'protocol').length})</h3>
                  <table className="tbl"><tbody>
                    {Object.entries(d.features).filter(([k]) => k !== 'protocol').map(([k, v]) => (
                      <tr key={k}><td className="text-ink-2">{FEATURE_LABEL[k] ?? k}</td><td className={`num ${v === null ? 'text-ink-3' : ''}`}>{fmtFeature(v)}</td></tr>
                    ))}
                  </tbody></table>
                </section>
              </>}
            </StateBlock>
          </Drawer>
        )}
      </div>
    </>
  );
};
