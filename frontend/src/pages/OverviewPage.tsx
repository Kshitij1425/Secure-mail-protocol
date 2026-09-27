import { Link } from 'react-router-dom';
import { useCapture } from '../context/CaptureContext';
import { getCapture, getCaptureAnomalies, getCaptureSessions, getPosture } from '../lib/api';
import { useAsync } from '../hooks/useAsync';
import { DimensionBars, SeverityDistribution } from '../components/charts';
import { Breadcrumbs, Mono, NeedCapture, PageTitle, Panel, Severity, StateBlock } from '../components/ui';
import { AnalystNotes } from '../components/AnalystNotes';
import { fmtScore, fmtUtc, shortSession } from '../lib/format';

const STATUS_NOTE: Record<string, string> = {
  Excellent: 'No significant weaknesses observed',
  Good: 'Minor weaknesses observed',
  'Needs Improvement': 'Weaknesses that should be scheduled for remediation',
  Poor: 'Serious weaknesses observed',
  Critical: 'Severe exposure observed',
  Unknown: 'Insufficient evidence: no assessable email session',
};

export const OverviewPage = () => {
  const { activeCaptureId, activeCapture } = useCapture();
  const done = activeCapture?.analysis_status === 'completed';
  const key = activeCaptureId && done ? activeCaptureId : null;
  const cap = useAsync(() => getCapture(activeCaptureId!), activeCaptureId);
  const posture = useAsync(() => getPosture(activeCaptureId!), key);
  const sessions = useAsync(() => getCaptureSessions(activeCaptureId!), key);
  const anomalies = useAsync(() => getCaptureAnomalies(activeCaptureId!), key);
  if (!activeCaptureId) return <NeedCapture />;

  const c = cap.data;
  const p = posture.data;
  const byProto = (sessions.data ?? []).reduce<Record<string, number>>((m, s) => ({ ...m, [s.protocol]: (m[s.protocol] ?? 0) + 1 }), {});
  const outliers = (anomalies.data ?? []).filter((a) => a.is_anomaly);

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: c?.filename ?? 'Analysis' }, { label: 'Posture' }]} />
      <StateBlock loading={cap.loading && !c} error={cap.error} onRetry={cap.reload}>
        {c && <>
          <PageTitle title="Security posture"
            lead={<>{c.filename}: captured {fmtUtc(c.capture_start)} to {fmtUtc(c.capture_end)}. Analysed {fmtUtc(c.analysis_timestamp)} in {c.analysis_duration_seconds?.toFixed(2) ?? '-'} s with the <strong>{c.policy_profile ?? 'balanced'}</strong> policy profile.</>}
            actions={<><Link to="/findings" className="btn">Review findings</Link><Link to="/reports" className="btn-primary">Report and export</Link></>} />

          {c.analysis_status !== 'completed' ? (
            <div role="alert" className="notice">Analysis status: {c.analysis_status}{c.analysis_error ? `. ${c.analysis_error}` : ''}</div>
          ) : (
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
              <Panel title="Posture score">
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-semibold tabular-nums" aria-label={`Posture score ${fmtScore(c.posture_score)}`}>{fmtScore(c.posture_score)}</span>
                  {c.posture_score !== null && <span className="text-ink-3">/ 100</span>}
                </div>
                <div className="mt-1 font-medium">{c.posture_status ?? 'Unknown'}</div>
                <p className="text-sm text-ink-2">{STATUS_NOTE[c.posture_status ?? 'Unknown']}</p>
                <div className="mt-4"><SeverityDistribution counts={c.severity_counts} /></div>
                <p className="mt-3 text-xs text-ink-3">Score from deterministic rules only. ML results never change it.</p>
              </Panel>

              <Panel title="What the capture contains">
                <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                  {[
                    ['Packets', c.packet_count.toLocaleString()],
                    ['Reassembled TCP streams', c.stream_count],
                    ['SMTP sessions', byProto.SMTP ?? 0],
                    ['IMAP sessions', byProto.IMAP ?? 0],
                    ['POP3 sessions', byProto.POP3 ?? 0],
                    ['Sessions with TLS observed', c.tls_session_count],
                    ['Certificates observed', c.certificates_count],
                    ['ML outliers', c.anomalies_count],
                  ].map(([k, v]) => (
                    <div key={k as string}><dt className="text-ink-3 text-xs">{k}</dt><dd className="text-lg font-semibold tabular-nums">{v}</dd></div>
                  ))}
                </dl>
                <p className="mt-3 text-xs text-ink-3">SHA-256 <Mono>{c.file_hash}</Mono></p>
              </Panel>

              <Panel title="Analysis record">
                <ol className="space-y-2 text-sm">
                  <li><span className="text-ink-3">Uploaded</span> {fmtUtc(c.upload_timestamp)}</li>
                  <li><span className="text-ink-3">Capture window</span> {fmtUtc(c.capture_start)} to {fmtUtc(c.capture_end)}</li>
                  <li><span className="text-ink-3">Frames</span> {String(c.ingestion.total_packets ?? c.packet_count)} total, {String(c.ingestion.malformed_packets ?? 0)} malformed{c.ingestion.truncated ? ', capture truncated' : ''}</li>
                  <li><span className="text-ink-3">Rules / scoring</span> v{c.rule_policy_version} / v{c.scoring_policy_version}, profile {c.policy_profile}</li>
                  <li><span className="text-ink-3">ML stage</span> {c.ml_status ?? 'not run'} ({c.ml_engine_version ?? 'n/a'})</li>
                  <li><span className="text-ink-3">Completed</span> {fmtUtc(c.analysis_timestamp)}</li>
                </ol>
                <Link to="/evidence" className="link text-sm mt-3 inline-block">Open the evidence register</Link>
              </Panel>
            </div>
          )}
        </>}
      </StateBlock>

      {done && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          <Panel title="Top security issues" actions={<Link to="/findings" className="link text-sm">All findings</Link>} bodyClass="">
            <StateBlock loading={posture.loading} error={posture.error} onRetry={posture.reload}
              empty={!!p && p.remediation_plan.length === 0} emptyText="No actionable findings in this analysis.">
              <table className="tbl">
                <thead><tr><th>#</th><th>Issue</th><th>Severity</th><th className="num">Sessions</th></tr></thead>
                <tbody>
                  {p?.remediation_plan.slice(0, 8).map((r) => (
                    <tr key={r.rule_id}>
                      <td className="tabular-nums text-ink-3">{r.priority}</td>
                      <td><Link to={`/findings?rule=${encodeURIComponent(r.rule_id)}`} className="link">{r.title}</Link><div className="text-xs text-ink-3 font-mono">{r.rule_id}</div></td>
                      <td><Severity value={r.severity} /></td>
                      <td className="num">{r.affected_sessions}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </StateBlock>
          </Panel>

          <Panel title="Posture by dimension" bodyClass="">
            <StateBlock loading={posture.loading} error={posture.error}>
              {p && <DimensionBars rows={p.dimension_scores.map((d) => ({ name: d.name, score: d.score, coverage: d.coverage_percent, quality: d.evidence_quality }))} />}
            </StateBlock>
          </Panel>

          <Panel title="Anomalous security configurations (ML, supplementary)" actions={<Link to="/anomalies" className="link text-sm">ML anomalies</Link>} bodyClass="">
            <StateBlock loading={anomalies.loading} error={anomalies.error}
              empty={!anomalies.loading && outliers.length === 0}
              emptyText={c?.ml_status?.startsWith('insufficient') ? 'Too few TLS sessions for anomaly detection in this capture.' : 'No session is weaker than, and unusual relative to, this capture baseline.'}>
              <table className="tbl">
                <thead><tr><th>Session</th><th>Level</th><th className="num">Score</th></tr></thead>
                <tbody>
                  {outliers.slice(0, 6).map((a) => (
                    <tr key={a.id}>
                      <td><Link className="link font-mono text-xs" to={`/anomalies?id=${a.id}`}>{shortSession(a.session_id)}</Link></td>
                      <td>{a.anomaly_level}</td>
                      <td className="num">{a.anomaly_score?.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-xs text-ink-3 px-3 py-2">Unusual relative to the capture baseline; requires investigation. Not a finding, attack or compromise verdict.</p>
            </StateBlock>
          </Panel>

          <Panel title="Investigation notes for this capture">
            <AnalystNotes captureId={activeCaptureId} targetType="capture" targetId={activeCaptureId} />
          </Panel>
        </div>
      )}
    </>
  );
};
