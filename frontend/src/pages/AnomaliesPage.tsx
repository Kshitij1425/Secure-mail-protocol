import { useEffect, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { getAnomalies, getAnomaly } from '../lib/api';
import type { AnomalySummary, AnomalyDetail as AnomalyDetailType } from '../types/api';
import { Sparkles, ArrowRight, X } from 'lucide-react';

export const AnomaliesPage = () => {
  const { activeCaptureId } = useCapture();
  const [anomalies, setAnomalies] = useState<AnomalySummary[]>([]);
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyDetailType | null>(null);

  useEffect(() => {
    let ignore = false;
    if (!activeCaptureId) {
      return;
    }

    const loadAnomalies = async () => {
      try {
        const data = await getAnomalies({ capture_id: activeCaptureId });
        if (!ignore) {
          setAnomalies(data);
          setSelectedAnomaly(null);
        }
      } catch (err) {
        if (!ignore) {
          console.error('Failed to load anomalies', err);
        }
      }
    };

    loadAnomalies();

    return () => {
      ignore = true;
    };
  }, [activeCaptureId]);

  const handleSelectAnomaly = async (id: number) => {
    try {
      const detail = await getAnomaly(id);
      setSelectedAnomaly(detail);
    } catch (e) {
      console.error(e);
    }
  };

  // Derive empty-state values during render instead of setting state in effect.
  const currentAnomalies = activeCaptureId ? anomalies : [];
  const currentSelectedAnomaly = activeCaptureId ? selectedAnomaly : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Sparkles className="text-amber-400" size={24} />
            ML Anomaly Detection Insights
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Unsupervised machine learning (Isolation Forest) identifying anomalous statistical outliers in TLS session patterns.
          </p>
        </div>
        <span className="bg-slate-800 text-slate-400 text-xs px-3 py-1.5 rounded-full font-mono">
          M11 IsolationForest
        </span>
      </div>

      <div className="bg-amber-950/20 border border-amber-800/40 rounded-lg p-4 text-xs text-amber-300/80 leading-relaxed">
        <strong>NOTE:</strong> ML anomaly detection outputs are purely supplementary diagnostic insights. They do not override deterministic M8 policy rules or ground-truth vulnerability findings.
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Anomaly List */}
        <div className={`space-y-3 ${currentSelectedAnomaly ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          {currentAnomalies.length === 0 ? (
            <div className="text-center py-12 bg-slate-900/20 border border-slate-800 rounded-lg text-slate-500">
              No ML anomalies flagged in this capture.
            </div>
          ) : (
            currentAnomalies.map((a) => (
              <div
                key={a.id}
                onClick={() => handleSelectAnomaly(a.id)}
                className={`p-4 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                  currentSelectedAnomaly?.id === a.id
                    ? 'bg-slate-800/80 border-amber-500/50'
                    : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-400">Session: {a.session_id}</span>
                  </div>
                  <div className="text-sm font-semibold text-slate-200">
                    Anomaly Score: {a.anomaly_score !== null ? a.anomaly_score.toFixed(3) : 'N/A'}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                    a.anomaly_level === 'severe'
                      ? 'bg-red-950 text-red-400 border border-red-800'
                      : a.anomaly_level === 'moderate'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                  }`}>
                    {a.anomaly_level}
                  </span>
                  <ArrowRight size={16} className="text-slate-600" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Anomaly Details */}
        {currentSelectedAnomaly && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6 h-fit sticky top-6">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono text-slate-500 uppercase">Session: {currentSelectedAnomaly.session_id}</span>
                <h3 className="text-lg font-bold text-slate-100 mt-1">Isolation Forest Diagnostic</h3>
              </div>
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="text-slate-500 hover:text-slate-300 p-1"
              >
                <X size={18} />
              </button>
            </div>

            <div className="space-y-4 text-sm divide-y divide-slate-800/60">
              <div className="pt-2">
                <span className="text-xs uppercase font-bold text-slate-400 block mb-1">Diagnostic Explanation</span>
                <p className="text-slate-300 leading-relaxed text-xs">
                  {currentSelectedAnomaly.explanation || 'No heuristic explanation generated for this feature vector.'}
                </p>
              </div>

              {currentSelectedAnomaly.features && (
                <div className="pt-4">
                  <span className="text-xs uppercase font-bold text-slate-400 block mb-2">Evaluated 10D Features</span>
                  <div className="bg-slate-950 p-3 rounded font-mono text-xs space-y-1 border border-slate-800 text-slate-300">
                    {Object.entries(currentSelectedAnomaly.features).map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span className="text-slate-500">{k}:</span>
                        <span>{typeof v === 'number' ? v.toFixed(2) : String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
