import { Link, useSearchParams } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getCompare } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { Breadcrumbs, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { fmtScore, fmtUtc } from '../lib/format';
import type { CompareFinding, CountDelta } from '../types/api';

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

export const ComparePage = () => {
  const { captures } = useCapture();
  const [params, setParams] = useSearchParams();
  const a = params.get('a') ?? '';
  const b = params.get('b') ?? '';
  const cmp = useAsync(() => getCompare(a, b), a && b && a !== b ? `${a}|${b}` : null);
  const set = (k: 'a' | 'b', v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); return n; });
  const done = captures.filter((c) => c.analysis_status === 'completed');
  const c = cmp.data;

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: 'Compare analyses' }]} />
      <PageTitle title="Compare analyses" lead="Differences between two stored analyses, for example before and after remediation. Findings are matched by rule and server (protocol, address, port). Nothing is recomputed or estimated." />
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
