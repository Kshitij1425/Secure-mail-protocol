import { Link, useSearchParams } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getCompare, getTrend } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { fmtScore, fmtUtc } from '../lib/format';
import type { CompareFinding, CountDelta, TrendPoint } from '../types/api';

const delta = (d: number | null) => (d === null ? 'n/a' : d > 0 ? `+${d}` : `${d}`);

const FindingTable = ({ rows, side, empty }: { rows: CompareFinding[]; side: 'a' | 'b' | 'both'; empty: string }) => (
  rows.length === 0 ? <p className="text-sm text-ink-2 px-4 py-3">{empty}</p> : (
    <table className="tbl">
      <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th className="num">Sessions A</th><th className="num">Sessions B</th></tr></thead>
      <tbody>
        {rows.map((f) => {
          return (
            <tr key={`${f.rule_id}|${f.asset}`}>
              <td><Severity value={(side === 'a' ? f.severity_a : f.severity_b) ?? 'INFO'} />{side === 'both' && f.severity_a !== f.severity_b && <div className="text-xs text-ink-3">was {f.severity_a?.toLowerCase()}</div>}</td>
              <td>{f.title}<div className="text-xs font-mono text-ink-3">{f.rule_id}</div></td>
              <td className="font-mono text-xs">{f.asset}</td>
              <td className="num">{f.sessions_a}</td><td className="num">{f.sessions_b}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  ));

const Counts = ({ title, rows }: { title: string; rows: CountDelta[] }) => (
  <Panel title={title} bodyClass="overflow-x-auto">
    {rows.length === 0 ? <p className="text-sm text-ink-2 px-4 py-3">None observed.</p> : (
      <table className="tbl"><thead><tr><th>Value</th><th className="num">A</th><th className="num">B</th><th className="num">Change</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.key}><td className="font-mono text-xs break-all">{r.key}</td><td className="num">{r.a}</td><td className="num">{r.b}</td><td className="num">{delta(r.delta)}</td></tr>)}</tbody></table>
    )}
  </Panel>
);

/** Posture score over capture time for analyses that share a server; points only, no interpolation claims. */
const TrendChart = ({ points }: { points: TrendPoint[] }) => {
  const pts = points.filter((p) => p.posture_score !== null);
  if (pts.length < 2) return <p className="text-sm text-ink-2 px-4 py-3">At least two scored analyses are needed to draw a trend.</p>;
  const W = 640, H = 190, L = 36, R = 24, T = 26, B = 28;
  const x = (i: number) => L + (i * (W - L - R)) / (pts.length - 1);
  const y = (v: number) => T + ((100 - v) * (H - T - B)) / 100;
  return (
    <figure className="px-4 py-3">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full max-w-3xl" role="img"
        aria-label={`Posture score by capture time: ${pts.map((p) => `${p.filename} ${Math.round(p.posture_score!)}`).join(', ')}`}>
        {[0, 50, 100].map((v) => <g key={v}><line x1={L} x2={W - R} y1={y(v)} y2={y(v)} stroke="rgb(var(--line))" /><text x={L - 6} y={y(v) + 4} textAnchor="end" fontSize="10" fill="rgb(var(--ink-3))">{v}</text></g>)}
        <polyline fill="none" stroke="rgb(var(--signal))" strokeWidth="2" points={pts.map((p, i) => `${x(i)},${y(p.posture_score!)}`).join(' ')} />
        {pts.map((p, i) => (
          <g key={p.capture_id}>
            <circle cx={x(i)} cy={y(p.posture_score!)} r={p.is_selected ? 6 : 4.5} fill={p.is_selected ? 'rgb(var(--signal))' : 'rgb(var(--panel))'} stroke="rgb(var(--signal))" strokeWidth="2"><title>{`${p.filename}: ${Math.round(p.posture_score!)} (${p.posture_status})`}</title></circle>
            <text x={x(i)} y={y(p.posture_score!) - 9} textAnchor="middle" fontSize="10" fill="rgb(var(--ink))">{Math.round(p.posture_score!)}</text>
            <text x={x(i)} y={H - 10} textAnchor="middle" fontSize="10" fill="rgb(var(--ink-3))">{i + 1}</text>
          </g>
        ))}
      </svg>
      <figcaption className="text-xs text-ink-3">Posture score (0-100) per analysis, ordered by capture time; numbers below the axis refer to the table rows. The filled point is the selected analysis.</figcaption>
    </figure>
  );
};

const Trend = ({ captureId }: { captureId: string }) => {
  const t = useAsync(() => getTrend(captureId), captureId);
  return (
    <Panel title="Posture trend for servers in the selected analysis" bodyClass="">
      <StateBlock loading={t.loading} error={t.error} onRetry={t.reload} empty={!!t.data && t.data.length === 0}
        emptyText="The selected analysis has no email sessions to relate to other analyses.">
        {t.data && <>
          <TrendChart points={t.data} />
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th className="sno">S. No.</th><th>Captured (UTC)</th><th>Analysis</th><th>Policy</th><th className="num">Score</th><th className="num">Findings</th><th className="num">Critical + high</th><th>Shared servers</th></tr></thead>
              <tbody>
                {t.data.map((p, i) => (
                  <tr key={p.capture_id} aria-current={p.is_selected ? 'true' : undefined} className={p.is_selected ? 'bg-signal-soft' : ''}>
                    <td className="sno">{i + 1}</td>
                    <td className="whitespace-nowrap tabular-nums">{fmtUtc(p.capture_start)}</td>
                    <td className="break-all">{p.filename}{p.is_selected && <span className="text-xs text-ink-3"> (selected)</span>}<div className="text-xs font-mono text-ink-3">{p.file_hash.slice(0, 12)}</div></td>
                    <td>{p.policy_profile}</td>
                    <td className="num font-semibold">{fmtScore(p.posture_score)}</td>
                    <td className="num">{p.findings_count}</td>
                    <td className="num">{p.severe_findings_count}</td>
                    <td className="font-mono text-xs">{p.shared_servers.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-ink-3 px-3 py-2">Analyses are related when they share at least one mail server (protocol, address and port). This is an association by address, not proof of identity. Re-analyses of the same file (same SHA-256) appear separately and may use different policy profiles, so score changes can reflect policy rather than configuration.</p>
        </>}
      </StateBlock>
    </Panel>
  );
};

export const ComparePage = () => {
  const { captures, activeCaptureId } = useCapture();
  const [params, setParams] = useSearchParams();
  const a = params.get('a') ?? '';
  const b = params.get('b') ?? '';
  const cmp = useAsync(() => getCompare(a, b), a && b && a !== b ? `${a}|${b}` : null);
  const set = (k: 'a' | 'b', v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); return n; });
  const done = captures.filter((c) => c.analysis_status === 'completed');
  const c = cmp.data;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: 'Compare and trend' }]} />
      <PageTitle title="Compare and trend" lead="Differences between two stored analyses, for example before and after remediation, and the posture history of the servers in the selected analysis. Findings are matched by rule and server (protocol, address, port). Nothing is recomputed or estimated." />
      {activeCaptureId && <Trend captureId={activeCaptureId} />}
      <h2 className="text-lg pt-2">Compare two analyses</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {(['a', 'b'] as const).map((k) => (
          <label key={k} className="flex flex-col gap-1"><span className="label">{k === 'a' ? 'A: baseline (earlier)' : 'B: comparison (later)'}</span>
            <select className="field" value={k === 'a' ? a : b} onChange={(e) => set(k, e.target.value)}>
              <option value="">Choose an analysis</option>
              {done.map((x) => <option key={x.capture_id} value={x.capture_id}>{x.filename} - {x.policy_profile} - score {fmtScore(x.posture_score)} - {fmtUtc(x.capture_start)}</option>)}
            </select></label>
        ))}
      </div>
      {!(a && b) && <p className="text-sm text-ink-2">Choose two analyses. You can also select two rows on the Captures page.</p>}
      {a && b && a === b && <p className="text-sm text-sev-high">Choose two different analyses.</p>}

      <StateBlock loading={cmp.loading} error={cmp.error} onRetry={cmp.reload}>
        {c && <>
          {c.notes.map((n) => <p key={n} className="notice">{n}</p>)}
          <Panel title="Posture change" bodyClass="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th /><th>A: {c.a.filename}</th><th>B: {c.b.filename}</th><th className="num">Change</th></tr></thead>
              <tbody>
                <tr><td>Posture score</td><td className="font-semibold">{fmtScore(c.posture.score_a)} ({c.posture.status_a})</td><td className="font-semibold">{fmtScore(c.posture.score_b)} ({c.posture.status_b})</td><td className="num font-semibold">{delta(c.posture.delta)}</td></tr>
                {c.posture.dimensions.map((d) => <tr key={d.dimension}><td className="text-ink-2">{d.name}</td><td>{fmtScore(d.a)}</td><td>{fmtScore(d.b)}</td><td className="num">{delta(d.delta)}</td></tr>)}
                <tr><td className="text-ink-2">Findings</td><td>{c.a.findings}</td><td>{c.b.findings}</td><td className="num">{delta(c.b.findings - c.a.findings)}</td></tr>
                <tr><td className="text-ink-2">ML outliers</td><td>{c.anomalies.a}</td><td>{c.anomalies.b}</td><td className="num">{delta(c.anomalies.delta)}</td></tr>
                <tr><td className="text-ink-2">Email sessions</td><td>{c.a.email_sessions}</td><td>{c.b.email_sessions}</td><td className="num">{delta(c.b.email_sessions - c.a.email_sessions)}</td></tr>
                <tr><td className="text-ink-2">Policy profile</td><td>{c.a.policy_profile}</td><td>{c.b.policy_profile}</td><td /></tr>
                <tr><td className="text-ink-2">Captured</td><td>{fmtUtc(c.a.captured_at)}</td><td>{fmtUtc(c.b.captured_at)}</td><td /></tr>
              </tbody>
            </table>
          </Panel>
          <div className="grid grid-cols-1 2xl:grid-cols-2 gap-5">
            <Panel title={`Resolved in B (${c.findings.resolved.length})`} bodyClass="overflow-x-auto"><FindingTable rows={c.findings.resolved} side="a" empty="No findings from A are absent in B." /></Panel>
            <Panel title={`New in B (${c.findings.new.length})`} bodyClass="overflow-x-auto"><FindingTable rows={c.findings.new} side="b" empty="No new findings in B." /></Panel>
          </div>
          <Panel title={`Present in both (${c.findings.persisting.length})`} bodyClass="overflow-x-auto"><FindingTable rows={c.findings.persisting} side="both" empty="No finding persists across both analyses." /></Panel>
          <Panel title="Server configuration changes" bodyClass="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Server</th><th>Present in</th><th>TLS versions A to B</th><th>Cipher suites A to B</th><th>Server certificate</th></tr></thead>
              <tbody>
                {c.assets.map((x) => (
                  <tr key={x.asset}>
                    <td className="font-mono text-xs">{x.asset}</td>
                    <td>{x.present_in === 'both' ? 'both' : x.present_in === 'a' ? 'A only' : 'B only'}</td>
                    <td className={x.tls_versions.changed ? 'font-medium' : 'text-ink-2'}>{x.tls_versions.a.join(', ') || '-'} to {x.tls_versions.b.join(', ') || '-'}</td>
                    <td className={`font-mono text-xs ${x.cipher_suites.changed ? 'font-medium' : 'text-ink-2'}`}>{x.cipher_suites.a.join(', ') || '-'}<br />to {x.cipher_suites.b.join(', ') || '-'}</td>
                    <td className="text-xs">{x.leaf_certificates.changed ? 'Replaced' : 'Unchanged'}
                      {x.leaf_certificates.a.map((l) => <div key={l.fingerprint_sha256} className="text-ink-3">A: {l.public_key}, {l.is_expired ? 'expired' : `until ${fmtUtc(l.not_after).slice(0, 10)}`}</div>)}
                      {x.leaf_certificates.b.map((l) => <div key={l.fingerprint_sha256} className="text-ink-3">B: {l.public_key}, {l.is_expired ? 'expired' : `until ${fmtUtc(l.not_after).slice(0, 10)}`}</div>)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
            <Counts title="TLS versions (sessions)" rows={c.tls_versions} />
            <Counts title="Cipher suites (sessions)" rows={c.cipher_suites} />
            <Counts title="Protocols (sessions)" rows={c.protocols} />
          </div>
          <p className="text-xs text-ink-3">{c.method} <Link className="link" to="/captures">Back to captures</Link></p>
        </>}
      </StateBlock>
    </>
  );
};
