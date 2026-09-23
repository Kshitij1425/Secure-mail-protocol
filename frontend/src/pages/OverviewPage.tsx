import { useEffect, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { getCapture, getFindings, getAnomalies } from '../lib/api';
import type { CaptureDetail, FindingSummary, AnomalySummary } from '../types/api';
import { PostureScore } from '../components/PostureScore';
import { MetricCard } from '../components/MetricCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { Activity, ShieldCheck, FileSearch, Lock, AlertOctagon } from 'lucide-react';
import { Link } from 'react-router-dom';

export const OverviewPage = () => {
  const { activeCaptureId } = useCapture();
  const [detail, setDetail] = useState<CaptureDetail | null>(null);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalySummary[]>([]);

  useEffect(() => {
    let ignore = false;
    if (!activeCaptureId) {
      return;
    }

    const loadData = async () => {
      try {
        const [cap, fnd, anm] = await Promise.all([
          getCapture(activeCaptureId),
          getFindings({ capture_id: activeCaptureId }),
          getAnomalies({ capture_id: activeCaptureId }),
        ]);
        if (!ignore) {
          setDetail(cap);
          setFindings(fnd);
          setAnomalies(anm);
        }
      } catch (err) {
        if (!ignore) {
          console.error('Failed to load overview data', err);
        }
      }
    };

    loadData();

    return () => {
      ignore = true;
    };
  }, [activeCaptureId]);

  // Derive empty-state values during render instead of setting state in effect.
  const currentDetail = activeCaptureId ? detail : null;
  const currentFindings = activeCaptureId ? findings : [];
  const currentAnomalies = activeCaptureId ? anomalies : [];

  if (!activeCaptureId) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
        <ShieldCheck size={48} className="text-slate-600 mb-4" />
        <h3 className="text-lg font-semibold text-slate-300">No Capture Selected</h3>
        <p className="text-sm text-slate-500 max-w-sm mt-1">Upload a PCAP capture or select an existing one from the top bar to inspect security posture.</p>
        <Link to="/upload" className="mt-6 bg-amber-500 hover:bg-amber-400 text-slate-950 px-4 py-2 rounded-lg font-bold text-sm">
          Upload PCAP
        </Link>
      </div>
    );
  }

  const criticalCount = currentFindings.filter(f => f.severity.toLowerCase() === 'critical').length;
  const highCount = currentFindings.filter(f => f.severity.toLowerCase() === 'high').length;
  const mediumCount = currentFindings.filter(f => f.severity.toLowerCase() === 'medium').length;
  const lowCount = currentFindings.filter(f => f.severity.toLowerCase() === 'low').length;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex items-center justify-between bg-slate-900/40 p-4 rounded-lg border border-slate-800">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-tight">{currentDetail?.filename || 'Capture Forensic Overview'}</h2>
          <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 font-mono">
            <span>SHA-256: {currentDetail?.file_hash?.slice(0, 16)}...</span>
            <span>Policy: {currentDetail?.scoring_policy_version || 'NIST SP 800-52r2'}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <Link to="/findings" className="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded text-xs font-semibold text-slate-200">
            View Findings
          </Link>
          <Link to="/sessions" className="bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded text-xs font-semibold text-slate-200">
            Inspect Sessions
          </Link>
        </div>
      </div>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Posture Score */}
        <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 flex flex-col items-center justify-center">
          <span className="text-xs uppercase tracking-widest text-slate-400 font-bold mb-4">Security Posture</span>
          <PostureScore score={Math.round(currentDetail?.posture_score || 0)} status={currentDetail?.posture_status || 'UNKNOWN'} />
        </div>

        {/* Metrics Column */}
        <div className="md:col-span-3 grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard label="Total Packets" value={currentDetail?.packet_count?.toLocaleString() || 0} icon={<Activity size={20} />} />
          <MetricCard label="Email Sessions" value={currentDetail?.email_session_count || 0} icon={<Lock size={20} />} />
          <MetricCard label="TLS Handshakes" value={currentDetail?.tls_session_count || 0} icon={<ShieldCheck size={20} />} />
          <MetricCard label="ML Anomalies" value={currentAnomalies.filter(a => a.is_anomaly).length} icon={<FileSearch size={20} />} />

          {/* Severity Counters */}
          <MetricCard label="Critical Issues" value={criticalCount} sub="Immediate Action" />
          <MetricCard label="High Issues" value={highCount} sub="High Risk" />
          <MetricCard label="Medium Issues" value={mediumCount} sub="Moderate Risk" />
          <MetricCard label="Low / Info" value={lowCount} sub="Advisory" />
        </div>
      </div>

      {/* Findings Preview */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <AlertOctagon size={18} className="text-amber-400" />
            Top Security Findings ({currentFindings.length})
          </h3>
          <Link to="/findings" className="text-xs text-amber-400 hover:text-amber-300 font-semibold">
            View All →
          </Link>
        </div>

        {currentFindings.length === 0 ? (
          <div className="text-sm text-slate-500 py-4 text-center">No security findings detected in this capture.</div>
        ) : (
          <div className="divide-y divide-slate-800">
            {currentFindings.slice(0, 5).map((f) => (
              <div key={f.finding_id} className="py-3 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="text-sm font-medium text-slate-200">{f.title}</span>
                </div>
                <span className="text-xs text-slate-500 font-mono">{f.rule_id}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
