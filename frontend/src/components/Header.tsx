import { useCapture } from '../context/CaptureContext';
import { Database, RefreshCw, AlertCircle, CheckCircle2, XCircle } from 'lucide-react';

export const Header = () => {
  const { activeCaptureId, setActiveCaptureId, captures, activeCapture, loading, error, refreshCaptures } = useCapture();

  return (
    <header className="min-h-16 bg-slate-900/60 border-b border-slate-800 px-6 py-2 flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        <Database size={18} className="text-amber-400 shrink-0" />
        <label htmlFor="capture-select" className="text-xs uppercase tracking-wider font-semibold text-slate-400 shrink-0">
          Capture
        </label>
        <select
          id="capture-select"
          value={activeCaptureId || ''}
          onChange={(e) => setActiveCaptureId(e.target.value || null)}
          className="bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded px-3 py-1.5 focus:outline-none focus:border-amber-500 font-mono max-w-[28rem] truncate"
        >
          {captures.length === 0 ? (
            <option value="">No captures loaded</option>
          ) : (
            captures.map((c) => (
              <option key={c.capture_id} value={c.capture_id}>
                {c.filename} ({c.capture_id.slice(0, 8)}) - {c.analysis_status}
              </option>
            ))
          )}
        </select>
        <button
          type="button"
          onClick={() => void refreshCaptures()}
          disabled={loading}
          aria-label="Refresh captures"
          title="Refresh captures"
          className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="flex items-center gap-2 text-xs font-medium">
        {error ? (
          <span className="flex items-center gap-2 text-red-300"><AlertCircle size={14} /> {error}</span>
        ) : activeCapture?.analysis_status === 'completed' ? (
          <span className="flex items-center gap-2 text-emerald-300"><CheckCircle2 size={14} /> Analysis complete</span>
        ) : activeCapture?.analysis_status === 'failed' ? (
          <span className="flex items-center gap-2 text-red-300"><XCircle size={14} /> Analysis failed: {activeCapture.analysis_error || 'unknown error'}</span>
        ) : activeCapture ? (
          <span className="text-amber-300">Status: {activeCapture.analysis_status}</span>
        ) : (
          <span className="flex items-center gap-2 text-amber-400/80"><AlertCircle size={14} /> No capture selected</span>
        )}
      </div>
    </header>
  );
};
