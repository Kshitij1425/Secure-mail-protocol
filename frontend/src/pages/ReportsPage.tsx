import { useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { bundleUrl, createReport, download, errorMessage, getAnnotations, getReports, reportDownloadUrl, stixUrl } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, Mono, NeedCapture, PageTitle, Panel, StateBlock } from '../components/ui';
import { fmtUtc } from '../lib/format';

export const ReportsPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const [redact, setRedact] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const reports = useAsync(() => getReports(activeCaptureId!), activeCaptureId);
  const notes = useAsync(() => getAnnotations(activeCaptureId!), activeCaptureId);
  const selected = (notes.data ?? []).filter((n) => n.include_in_report).length;
  if (!activeCaptureId) return <NeedCapture />;
  const ready = activeCapture?.analysis_status === 'completed';

  const make = async (fmt: 'json' | 'html' | 'pdf') => {
    setBusy(fmt);
    setErr(null);
    try {
      const r = await createReport(activeCaptureId, fmt, redact);
      reports.reload();
      download(reportDownloadUrl(r.report_id));
    } catch (e) {
      setErr(errorMessage(e, 'Report generation failed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: activeCapture?.filename ?? 'Analysis', to: '/' }, { label: 'Report' }]} />
      <PageTitle title="Report and export" lead="Every output is generated from the stored analysis and records the capture SHA-256, analysis time, tool version and policy profile." />

      <Panel title="Output mode">
        <fieldset className="space-y-2 text-sm">
          <legend className="sr-only">Output mode</legend>
          <label className="flex items-start gap-2"><input type="radio" name="mode" checked={!redact} onChange={() => setRedact(false)} className="mt-1" />
            <span><strong>Raw</strong>: complete values, including IP addresses and host names.</span></label>
          <label className="flex items-start gap-2"><input type="radio" name="mode" checked={redact} onChange={() => setRedact(true)} className="mt-1" />
            <span><strong>Redacted</strong>: IP addresses, host names, organisation names, e-mail addresses and the file name are replaced by consistent pseudonyms.
            Cryptographic evidence is kept. Fingerprints and serial numbers remain and can be looked up in public Certificate Transparency logs.</span></label>
        </fieldset>
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <Panel title="Forensic report">
          <p className="text-sm text-ink-2 mb-3">Fourteen sections from executive summary to integrity information, identical in JSON, HTML and PDF. JSON is the canonical machine-readable document.</p>
          <p className="text-sm mb-3">{notes.loading ? 'Checking analyst selections' : selected
            ? <>Appendix A will contain <strong>{selected}</strong> item(s) you selected for the investigation report.</>
            : <>No items are selected for the report appendix. Use "Include in investigation report" in a finding, session or certificate, or on the Posture page.</>}</p>
          <div className="flex flex-wrap gap-2">
            {(['pdf', 'html', 'json'] as const).map((f) => (
              <button key={f} type="button" className={f === 'pdf' ? 'btn-primary' : 'btn'} disabled={!ready || busy !== null} onClick={() => void make(f)}>
                {busy === f ? 'Generating' : `Download ${f.toUpperCase()}`}{redact ? ' (redacted)' : ''}
              </button>
            ))}
          </div>
        </Panel>
        <Panel title="Evidence bundle and exchange formats">
          <p className="text-sm text-ink-2 mb-3">The evidence bundle is a deterministic ZIP of JSON files (findings, sessions, certificates, anomalies, timeline, remediation) with a SHA-256 manifest. It contains no packet payloads. STIX 2.1 exports observations and posture notes only; it contains no indicators of compromise.</p>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn" disabled={!ready} onClick={() => download(bundleUrl(activeCaptureId, redact))}>Download evidence bundle{redact ? ' (redacted)' : ''}</button>
            <button type="button" className="btn" disabled={!ready} onClick={() => download(stixUrl(activeCaptureId, redact))}>Download STIX 2.1{redact ? ' (redacted)' : ''}</button>
          </div>
        </Panel>
      </div>
      {err && <p role="alert" className="text-sm text-sev-high">{err}</p>}

      <Panel title="Generated reports" bodyClass="overflow-x-auto">
        <StateBlock loading={reports.loading} error={reports.error} onRetry={reports.reload}
          empty={!!reports.data && reports.data.length === 0} emptyText="No reports generated for this analysis yet.">
          <table className="tbl">
            <thead><tr><th>Created</th><th>Format</th><th>Mode</th><th className="num">Size</th><th>SHA-256</th><th /></tr></thead>
            <tbody>
              {reports.data?.map((r) => (
                <tr key={r.report_id}>
                  <td className="whitespace-nowrap">{fmtUtc(r.created_at)}</td>
                  <td>{r.report_type.toUpperCase()}</td>
                  <td>{r.redacted ? 'Redacted' : 'Raw'}</td>
                  <td className="num">{(r.file_size / 1024).toFixed(1)} KB</td>
                  <td className="text-xs"><Mono>{r.sha256}</Mono></td>
                  <td><button type="button" className="link text-sm" onClick={() => download(reportDownloadUrl(r.report_id))}>Download</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </StateBlock>
      </Panel>
    </>
  );
};
