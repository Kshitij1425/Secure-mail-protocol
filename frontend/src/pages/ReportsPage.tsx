import { useRef, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { bundleUrl, createReport, download, errorMessage, getAnnotations, getReportPreview, getReports, reportDownloadUrl, stixUrl } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, KV, Mono, NeedCapture, PageTitle, Panel, StateBlock } from '../components/ui';
import { fmtScore, fmtUtc } from '../lib/format';

export const ReportsPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const [redact, setRedact] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const reports = useAsync(() => getReports(activeCaptureId!), activeCaptureId);
  const notes = useAsync(() => getAnnotations(activeCaptureId!), activeCaptureId);
  const selected = (notes.data ?? []).filter((n) => n.include_in_report).length;
  const [previewOn, setPreviewOn] = useState(false);
  const preview = useAsync(() => getReportPreview(activeCaptureId!, redact), previewOn && activeCaptureId ? `${activeCaptureId}|${redact}` : null);
  const frame = useRef<HTMLIFrameElement>(null);
  const jump = (anchor: string) => frame.current?.contentDocument?.getElementById(anchor)?.scrollIntoView({ block: 'start' });
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

      <Panel title="1. Output mode">
        <fieldset className="space-y-2 text-sm">
          <legend className="sr-only">Output mode</legend>
          <label className="flex items-start gap-2"><input type="radio" name="mode" checked={!redact} onChange={() => setRedact(false)} className="mt-1" />
            <span><strong>Raw</strong>: complete values, including IP addresses and host names.</span></label>
          <label className="flex items-start gap-2"><input type="radio" name="mode" checked={redact} onChange={() => setRedact(true)} className="mt-1" />
            <span><strong>Redacted</strong>: IP addresses, host names, organisation names, e-mail addresses and the file name are replaced by consistent pseudonyms.
            Cryptographic evidence is kept. Fingerprints and serial numbers remain and can be looked up in public Certificate Transparency logs.</span></label>
        </fieldset>
      </Panel>

      <Panel title={`2. Preview the ${redact ? 'redacted' : 'raw'} report`}
        actions={previewOn ? <button type="button" className="btn" onClick={() => setPreviewOn(false)}>Close preview</button> : undefined}>
        {!previewOn ? (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <button type="button" className="btn-primary" disabled={!ready} onClick={() => setPreviewOn(true)}>Preview report</button>
            <span className="text-ink-2">Shows the HTML report exactly as it will be downloaded, before any file is written.</span>
          </div>
        ) : (
          <StateBlock loading={preview.loading} error={preview.error} onRetry={preview.reload}>
            {preview.data && (
              <div className="grid grid-cols-1 xl:grid-cols-[16rem_minmax(0,1fr)] gap-4">
                <div className="space-y-3 text-sm">
                  <KV rows={[
                    { k: 'Mode', v: <strong>{preview.data.mode === 'REDACTED' ? 'Redacted' : 'Raw'}</strong> },
                    { k: 'Policy', v: preview.data.policy_profile },
                    { k: 'Posture', v: `${fmtScore(preview.data.score)} / 100 (${preview.data.status})` },
                    { k: 'Findings', v: preview.data.findings },
                    { k: 'Appendix A', v: preview.data.selected_annotations ? `${preview.data.selected_annotations} selected item(s)` : 'none' },
                    { k: 'Capture', v: <Mono>{preview.data.capture_sha256.slice(0, 16)}...</Mono> },
                  ]} />
                  <nav aria-label="Report sections">
                    <div className="label mb-1">Sections</div>
                    <ol className="space-y-0.5">
                      {preview.data.sections.map((sec) => (
                        <li key={sec.anchor}><button type="button" className="link text-left text-sm py-1 inline-block min-h-[24px]" onClick={() => jump(sec.anchor)}>{sec.number}. {sec.title}</button></li>
                      ))}
                    </ol>
                  </nav>
                </div>
                <iframe ref={frame} title={`Report preview (${preview.data.mode === 'REDACTED' ? 'redacted' : 'raw'})`}
                  sandbox="allow-same-origin" srcDoc={preview.data.html}
                  className="w-full h-[70vh] min-h-[28rem] border border-line rounded bg-white" />
              </div>
            )}
          </StateBlock>
        )}
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <Panel title="3. Download the forensic report">
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
