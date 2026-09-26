import { useState } from 'react';
import { FileDown, Loader2 } from 'lucide-react';
import { createReport, errorMessage, reportDownloadUrl } from '../lib/api';

const FORMATS = ['json', 'html', 'pdf'] as const;

/** Generates a report on the server, then downloads it (served as an attachment). */
export const ReportExport = ({ captureId }: { captureId: string }) => {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (fmt: (typeof FORMATS)[number]) => {
    setBusy(fmt);
    setError(null);
    try {
      const report = await createReport(captureId, fmt);
      const a = document.createElement('a');
      a.href = reportDownloadUrl(report.report_id);
      a.rel = 'noopener';
      a.click();
    } catch (e) {
      setError(errorMessage(e, 'Report generation failed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Export</span>
      {FORMATS.map((f) => (
        <button key={f} type="button" onClick={() => void run(f)} disabled={busy !== null}
          className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 px-3 py-1.5 rounded text-xs font-semibold text-slate-200 flex items-center gap-1.5">
          {busy === f ? <Loader2 size={12} className="animate-spin" /> : <FileDown size={12} />}
          {f.toUpperCase()}
        </button>
      ))}
      {error && <span role="alert" className="text-xs text-red-300">{error}</span>}
    </div>
  );
};
