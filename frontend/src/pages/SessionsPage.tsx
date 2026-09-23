import { useEffect, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { getCaptureSessions, getSession } from '../lib/api';
import type { SessionSummary, SessionDetail as SessionDetailType } from '../types/api';
import { ArrowRight, X } from 'lucide-react';

export const SessionsPage = () => {
  const { activeCaptureId } = useCapture();
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selectedSession, setSelectedSession] = useState<SessionDetailType | null>(null);

  useEffect(() => {
    let ignore = false;
    if (!activeCaptureId) {
      return;
    }

    const loadSessions = async () => {
      try {
        const data = await getCaptureSessions(activeCaptureId);
        if (!ignore) {
          setSessions(data);
          setSelectedSession(null);
        }
      } catch (err) {
        if (!ignore) {
          console.error('Failed to load sessions', err);
        }
      }
    };

    loadSessions();

    return () => {
      ignore = true;
    };
  }, [activeCaptureId]);

  const handleSelectSession = async (id: string) => {
    try {
      const detail = await getSession(id);
      setSelectedSession(detail);
    } catch (e) {
      console.error(e);
    }
  };

  // Derive empty-state values during render instead of setting state in effect.
  const currentSessions = activeCaptureId ? sessions : [];
  const currentSelectedSession = activeCaptureId ? selectedSession : null;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Session Explorer</h2>
        <p className="text-sm text-slate-400 mt-1">Reconstructed email TCP streams and negotiated TLS security properties.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sessions Table */}
        <div className={`space-y-3 ${currentSelectedSession ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          {currentSessions.length === 0 ? (
            <div className="text-center py-12 bg-slate-900/20 border border-slate-800 rounded-lg text-slate-500">
              No sessions detected in capture.
            </div>
          ) : (
            currentSessions.map((s) => (
              <div
                key={s.session_id}
                onClick={() => handleSelectSession(s.session_id)}
                className={`p-4 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                  currentSelectedSession?.session_id === s.session_id
                    ? 'bg-slate-800/80 border-amber-500/50'
                    : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="bg-slate-800 px-2 py-0.5 rounded text-[11px] font-mono font-bold text-amber-400 uppercase">
                      {s.protocol}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      {s.source_ip || '127.0.0.1'}:{s.source_port || 0} → {s.dest_ip || '127.0.0.1'}:{s.dest_port || 25}
                    </span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono">
                    TLS: {s.tls_version || 'Plaintext / Unencrypted'} · {s.cipher_suite || 'None'}
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {s.has_anomaly && (
                    <span className="bg-red-950 text-red-400 border border-red-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                      ML Anomaly
                    </span>
                  )}
                  {s.has_forward_secrecy ? (
                    <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                      PFS
                    </span>
                  ) : (
                    <span className="bg-slate-800 text-slate-400 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                      No PFS
                    </span>
                  )}
                  <ArrowRight size={16} className="text-slate-600" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Forensic Timeline & Session Details */}
        {currentSelectedSession && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6 h-fit sticky top-6">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono text-slate-500 uppercase">Session ID: {currentSelectedSession.session_id}</span>
                <h3 className="text-lg font-bold text-slate-100 mt-1">Stream Forensic Details</h3>
              </div>
              <button
                onClick={() => setSelectedSession(null)}
                className="text-slate-500 hover:text-slate-300 p-1"
              >
                <X size={18} />
              </button>
            </div>

            {/* Forensic Attribute List */}
            <div className="space-y-3 font-mono text-xs divide-y divide-slate-800/60">
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Protocol:</span>
                <span className="text-amber-400 font-bold">{currentSelectedSession.protocol}</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">STARTTLS Status:</span>
                <span className="text-slate-200">{currentSelectedSession.starttls_state || 'NOT OBSERVED'}</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">TLS Version:</span>
                <span className="text-slate-200">{currentSelectedSession.tls_version || 'NONE'}</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Cipher Suite:</span>
                <span className="text-slate-200 text-right max-w-[200px] truncate">{currentSelectedSession.cipher_suite || 'NONE'}</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Forward Secrecy:</span>
                <span className={currentSelectedSession.has_forward_secrecy ? 'text-emerald-400' : 'text-red-400'}>
                  {currentSelectedSession.has_forward_secrecy ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Handshake Complete:</span>
                <span className="text-slate-200">{currentSelectedSession.handshake_complete ? 'YES' : 'NO'}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
