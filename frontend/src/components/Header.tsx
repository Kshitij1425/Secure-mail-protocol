import { useCapture } from '../context/CaptureContext';
import { Database, RefreshCw, AlertCircle } from 'lucide-react';
import type { CaptureSummary } from '../types/api';

export const Header = () => {
  const { activeCaptureId, setActiveCaptureId, captures, loading, refreshCaptures } = useCapture();

  return (
    <header className="h-16 bg-slate-900/60 border-b border-slate-800 px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <Database size={18} className="text-amber-400" />
        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Target Capture:</span>
        <select
          value={activeCaptureId || ''}
          onChange={(e) => setActiveCaptureId(e.target.value || null)}
          className="bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded px-3 py-1.5 focus:outline-none focus:border-amber-500 font-mono"
        >
          {captures.length === 0 ? (
            <option value="">No captures loaded</option>
          ) : (
            captures.map((c: CaptureSummary) => (
              <option key={c.capture_id} value={c.capture_id}>
                {c.filename} ({c.capture_id.slice(0, 8)}) - {c.analysis_status.toUpperCase()}
              </option>
            ))
          )}
        </select>
        <button
          onClick={() => refreshCaptures()}
          disabled={loading}
          className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
          title="Refresh captures"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="flex items-center gap-4">
        {activeCaptureId ? (
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs text-slate-400 font-medium">Capture Loaded</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-amber-400/80">
            <AlertCircle size={14} />
            <span className="text-xs font-medium">No Capture Active</span>
          </div>
        )}
      </div>
    </header>
  );
};
