import { Severity } from './ui';

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const FILL: Record<string, string> = {
  CRITICAL: 'bg-sev-critical', HIGH: 'bg-sev-high', MEDIUM: 'bg-sev-medium', LOW: 'bg-sev-low', INFO: 'bg-sev-info',
};

/** Part-to-whole of findings by severity: one stacked bar, legend with counts (direct labels). */
export const SeverityDistribution = ({ counts }: { counts: Record<string, number> }) => {
  const total = SEVS.reduce((n, s) => n + (counts[s] ?? 0), 0);
  if (total === 0) return <p className="text-sm text-ink-2">No findings.</p>;
  return (
    <figure className="space-y-3">
      <div className="flex h-4 w-full gap-[2px]" role="img"
        aria-label={`Findings by severity: ${SEVS.map((s) => `${s.toLowerCase()} ${counts[s] ?? 0}`).join(', ')}`}>
        {SEVS.filter((s) => counts[s]).map((s) => (
          <div key={s} title={`${s.toLowerCase()}: ${counts[s]} finding(s)`} style={{ flexGrow: counts[s] }}
            className={`${FILL[s]} first:rounded-l last:rounded-r min-w-[6px]`} />
        ))}
      </div>
      <figcaption>
        <table className="text-sm">
          <caption className="sr-only">Findings by severity</caption>
          <tbody className="flex flex-wrap gap-x-5 gap-y-1">
            {SEVS.map((s) => (
              <tr key={s} className="flex items-center gap-2">
                <th scope="row" className="font-normal"><Severity value={s} compact /></th>
                <td className="tabular-nums font-medium">{counts[s] ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figcaption>
    </figure>
  );
};

/** Dimension scores 0-100: single-hue magnitude bars with the value labelled. */
export const DimensionBars = ({ rows }: { rows: { name: string; score: number | null; coverage: number; quality: string }[] }) => (
  <table className="tbl">
    <thead><tr><th>Dimension</th><th className="w-1/2">Score</th><th className="num">Coverage</th><th>Evidence</th></tr></thead>
    <tbody>
      {rows.map((r) => (
        <tr key={r.name}>
          <td>{r.name}</td>
          <td>
            {r.score === null ? <span className="text-ink-3">not assessable</span> : (
              <div className="flex items-center gap-2" title={`${r.name}: ${Math.round(r.score)} of 100`}>
                <div className="flex-1 h-2 bg-line rounded-sm"><div className="h-2 bg-signal rounded-sm" style={{ width: `${Math.max(1, r.score)}%` }} /></div>
                <span className="tabular-nums w-8 text-right">{Math.round(r.score)}</span>
              </div>
            )}
          </td>
          <td className="num">{Math.round(r.coverage)}%</td>
          <td className="text-ink-2">{r.quality.replace('_', ' ')}</td>
        </tr>
      ))}
    </tbody>
  </table>
);
