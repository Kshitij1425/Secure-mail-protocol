import { AlertTriangle, Loader2, Inbox } from 'lucide-react';
import type { ReactNode } from 'react';

interface Props {
  loading?: boolean;
  error?: string | null;
  empty?: boolean;
  emptyText?: string;
  onRetry?: () => void;
  children?: ReactNode;
}

/** Uniform loading / error / empty handling for every data view. */
export const StateBlock = ({ loading, error, empty, emptyText = 'Nothing to show.', onRetry, children }: Props) => {
  if (loading) {
    return (
      <div role="status" className="flex items-center gap-2 justify-center py-12 text-slate-400 text-sm">
        <Loader2 className="animate-spin" size={16} /> Loading...
      </div>
    );
  }
  if (error) {
    return (
      <div role="alert" className="bg-red-950/40 border border-red-800/70 text-red-200 px-4 py-3 rounded-lg flex items-center gap-3 text-sm">
        <AlertTriangle size={16} className="text-red-400 shrink-0" />
        <span className="flex-1">{error}</span>
        {onRetry && (
          <button type="button" onClick={onRetry} className="text-xs font-semibold underline hover:text-red-100">Retry</button>
        )}
      </div>
    );
  }
  if (empty) {
    return (
      <div className="text-center py-12 bg-slate-900/20 border border-slate-800 rounded-lg text-slate-500 text-sm flex flex-col items-center gap-2">
        <Inbox size={20} /> {emptyText}
      </div>
    );
  }
  return <>{children}</>;
};

export const DetailPanel = ({ title, subtitle, onClose, children }: {
  title: string; subtitle?: ReactNode; onClose: () => void; children: ReactNode;
}) => (
  <aside aria-label={title} className="bg-slate-900/70 border border-slate-800 rounded-xl p-6 space-y-5 h-fit lg:sticky lg:top-0 max-h-[calc(100vh-8rem)] overflow-y-auto">
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0">
        {subtitle && <div className="text-[11px] font-mono text-slate-500 break-all">{subtitle}</div>}
        <h3 className="text-lg font-bold text-slate-100 mt-1 break-words">{title}</h3>
      </div>
      <button type="button" onClick={onClose} aria-label="Close details"
        className="text-slate-400 hover:text-slate-100 p-1 rounded hover:bg-slate-800 shrink-0">✕</button>
    </div>
    {children}
  </aside>
);

export const Field = ({ label, children, mono = true }: { label: string; children: ReactNode; mono?: boolean }) => (
  <div className="flex justify-between gap-4 py-1.5 border-b border-slate-800/60 text-xs">
    <span className="text-slate-500 shrink-0">{label}</span>
    <span className={`text-slate-200 text-right break-all ${mono ? 'font-mono' : ''}`}>{children}</span>
  </div>
);
