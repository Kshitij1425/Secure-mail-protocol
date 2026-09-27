import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, ChevronRight, Inbox, Loader2, X } from 'lucide-react';

/* ---------------------------------------------------------------- severity */
const SEV_SWATCH: Record<string, string> = {
  CRITICAL: 'bg-sev-critical', HIGH: 'bg-sev-high', MEDIUM: 'bg-sev-medium', LOW: 'bg-sev-low', INFO: 'bg-sev-info',
};
const SEV_LABEL: Record<string, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' };

/** Severity is always text + an ordinal swatch, never colour alone. */
export const Severity = ({ value, compact = false }: { value: string; compact?: boolean }) => {
  const v = value.toUpperCase();
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden="true" className={`inline-block ${compact ? 'w-2 h-2' : 'w-2.5 h-2.5'} rounded-sm ${SEV_SWATCH[v] ?? 'bg-sev-info'}`} />
      <span className={`text-sm ${v === 'CRITICAL' || v === 'HIGH' ? 'font-semibold' : 'font-medium'} text-ink`}>{SEV_LABEL[v] ?? value}</span>
    </span>
  );
};

/* ---------------------------------------------------------------- evidence class */
const EVIDENCE: Record<string, { label: string; cls: string; hint: string }> = {
  OBSERVED: { label: 'Observed', cls: 'border-ok text-ok', hint: 'Directly visible in the capture' },
  INFERRED: { label: 'Inferred', cls: 'border-signal text-signal', hint: 'Derived from observed values' },
  POTENTIAL_INDICATOR: { label: 'Potential indicator', cls: 'border-warn text-warn', hint: 'Consistent with an attack or misconfiguration; not proof' },
  INSUFFICIENT_EVIDENCE: { label: 'Insufficient evidence', cls: 'border-ink-3 text-ink-3', hint: 'The capture does not contain enough data' },
  NOT_OBSERVABLE: { label: 'Not observable', cls: 'border-ink-3 text-ink-3', hint: 'Protocol hides this passively (e.g. TLS 1.3 certificates)' },
  NOT_OBSERVED: { label: 'Not observed', cls: 'border-ink-3 text-ink-3', hint: 'Absent from the capture' },
  PARTIAL: { label: 'Partially observed', cls: 'border-warn text-warn', hint: 'Only part of the exchange was captured' },
  NOT_EVALUATED: { label: 'Not evaluated', cls: 'border-ink-3 text-ink-3', hint: 'Requires context the capture cannot provide' },
  ML_ANOMALY: { label: 'ML outlier', cls: 'border-ml text-ml', hint: 'Statistical outlier; requires investigation' },
  ML_ASSESSMENT: { label: 'ML assessment', cls: 'border-ml text-ml', hint: 'Supplementary statistical result' },
};
export const EvidenceTag = ({ value }: { value: string | null | undefined }) => {
  const e = EVIDENCE[(value ?? '').toUpperCase()] ?? { label: value ?? 'unknown', cls: 'border-line-strong text-ink-2', hint: '' };
  return <span title={e.hint} className={`inline-block border rounded-sm px-1.5 py-px text-xs font-medium whitespace-nowrap ${e.cls}`}>{e.label}</span>;
};

/* ---------------------------------------------------------------- layout pieces */
export const Panel = ({ title, actions, children, bodyClass = 'panel-body', id }: {
  title: ReactNode; actions?: ReactNode; children: ReactNode; bodyClass?: string; id?: string;
}) => (
  <section className="panel" aria-labelledby={id}>
    <div className="panel-head">
      <h2 id={id} className="panel-title">{title}</h2>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
    <div className={bodyClass}>{children}</div>
  </section>
);

export const PageTitle = ({ title, lead, actions }: { title: string; lead?: ReactNode; actions?: ReactNode }) => (
  <div className="flex flex-wrap items-end justify-between gap-3">
    <div className="min-w-0">
      <h1 className="text-2xl">{title}</h1>
      {lead && <p className="text-sm text-ink-2 mt-1 max-w-[75ch]">{lead}</p>}
    </div>
    {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
  </div>
);

export const Breadcrumbs = ({ items }: { items: { label: string; to?: string }[] }) => (
  <nav aria-label="Breadcrumb" className="text-sm text-ink-3">
    <ol className="flex flex-wrap items-center gap-1">
      {items.map((it, i) => (
        <li key={i} className="flex items-center gap-1 min-w-0">
          {i > 0 && <ChevronRight size={14} aria-hidden="true" />}
          {it.to && i < items.length - 1 ? <Link to={it.to} className="link truncate">{it.label}</Link>
            : <span aria-current={i === items.length - 1 ? 'page' : undefined} className="text-ink-2 truncate max-w-[40ch]">{it.label}</span>}
        </li>
      ))}
    </ol>
  </nav>
);

export const KV = ({ rows }: { rows: { k: string; v: ReactNode }[] }) => (
  <dl className="kv">
    {rows.map(({ k, v }) => (
      <div key={k} className="contents"><dt>{k}</dt><dd>{v}</dd></div>
    ))}
  </dl>
);

export const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-[0.92em] break-all">{children}</span>;

/* ---------------------------------------------------------------- states */
export const StateBlock = ({ loading, error, empty, emptyText = 'Nothing to show.', emptyAction, onRetry, children }: {
  loading?: boolean; error?: string | null; empty?: boolean; emptyText?: string; emptyAction?: ReactNode;
  onRetry?: () => void; children?: ReactNode;
}) => {
  if (loading) {
    return <div role="status" className="flex items-center gap-2 py-8 justify-center text-sm text-ink-2"><Loader2 size={16} className="animate-spin" />Loading</div>;
  }
  if (error) {
    return (
      <div role="alert" className="border-l-4 border-sev-high bg-sev-low/15 px-3 py-2.5 text-sm flex items-center gap-3">
        <AlertTriangle size={16} className="text-sev-high shrink-0" aria-hidden="true" />
        <span className="flex-1">{error}</span>
        {onRetry && <button type="button" className="btn" onClick={onRetry}>Retry</button>}
      </div>
    );
  }
  if (empty) {
    return (
      <div className="py-10 flex flex-col items-center gap-3 text-sm text-ink-2">
        <Inbox size={20} aria-hidden="true" className="text-ink-3" />
        <span>{emptyText}</span>
        {emptyAction}
      </div>
    );
  }
  return <>{children}</>;
};

/** Right-hand detail drawer: stays in the page flow on wide screens, overlays on narrow ones. */
export const Drawer = ({ title, subtitle, onClose, children }: {
  title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode;
}) => (
  <aside aria-label="Details" className="panel self-start lg:sticky lg:top-4 max-h-[calc(100vh-7rem)] overflow-y-auto">
    <div className="panel-head sticky top-0 z-10">
      <div className="min-w-0">
        <h2 className="panel-title break-words">{title}</h2>
        {subtitle && <div className="text-xs text-ink-3 font-mono break-all mt-0.5">{subtitle}</div>}
      </div>
      <button type="button" onClick={onClose} aria-label="Close details" className="p-1 rounded hover:bg-line/60 text-ink-2"><X size={16} /></button>
    </div>
    <div className="panel-body space-y-5">{children}</div>
  </aside>
);

export const NeedCapture = () => (
  <StateBlock empty emptyText="No analysis selected. Open one from Captures or analyse a new capture."
    emptyAction={<div className="flex gap-2"><Link to="/captures" className="btn">Open captures</Link><Link to="/upload" className="btn-primary">Analyse a capture</Link></div>} />
);
