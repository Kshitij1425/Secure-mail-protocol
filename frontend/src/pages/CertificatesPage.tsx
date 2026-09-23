import { useEffect, useState } from 'react';
import { useCapture } from '../context/CaptureContext';
import { getCertificates, getCertificate } from '../lib/api';
import type { CertificateSummary, CertificateDetail as CertificateDetailType } from '../types/api';
import { Receipt, ArrowRight, X } from 'lucide-react';

export const CertificatesPage = () => {
  const { activeCaptureId } = useCapture();
  const [certificates, setCertificates] = useState<CertificateSummary[]>([]);
  const [selectedCert, setSelectedCert] = useState<CertificateDetailType | null>(null);

  useEffect(() => {
    let ignore = false;
    if (!activeCaptureId) {
      return;
    }

    const loadCerts = async () => {
      try {
        const data = await getCertificates({ capture_id: activeCaptureId });
        if (!ignore) {
          setCertificates(data);
          setSelectedCert(null);
        }
      } catch (err) {
        if (!ignore) {
          console.error('Failed to load certificates', err);
        }
      }
    };

    loadCerts();

    return () => {
      ignore = true;
    };
  }, [activeCaptureId]);

  const handleSelectCert = async (fp: string) => {
    try {
      const detail = await getCertificate(fp);
      setSelectedCert(detail);
    } catch (e) {
      console.error(e);
    }
  };

  // Derive empty-state values during render instead of setting state in effect.
  const currentCertificates = activeCaptureId ? certificates : [];
  const currentSelectedCert = activeCaptureId ? selectedCert : null;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Certificate Inventory</h2>
        <p className="text-sm text-slate-400 mt-1">X.509 certificates extracted passively from observed TLS Server Certificate handshakes.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Certificate List */}
        <div className={`space-y-3 ${currentSelectedCert ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          {currentCertificates.length === 0 ? (
            <div className="text-center py-12 bg-slate-900/20 border border-slate-800 rounded-lg text-slate-500">
              No certificates observed in capture.
            </div>
          ) : (
            currentCertificates.map((c) => (
              <div
                key={c.fingerprint_sha256}
                onClick={() => handleSelectCert(c.fingerprint_sha256)}
                className={`p-4 rounded-lg border transition-all cursor-pointer flex items-center justify-between ${
                  currentSelectedCert?.fingerprint_sha256 === c.fingerprint_sha256
                    ? 'bg-slate-800/80 border-amber-500/50'
                    : 'bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Receipt size={16} className="text-amber-400" />
                    <span className="text-sm font-semibold text-slate-200">{c.subject}</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Issuer: {c.issuer}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    {c.public_key_algorithm} {c.public_key_size_bits ? `(${c.public_key_size_bits} bit)` : ''}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  {c.is_expired ? (
                    <span className="bg-red-950 text-red-400 border border-red-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                      Expired
                    </span>
                  ) : (
                    <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] px-2 py-0.5 rounded font-bold uppercase">
                      Valid
                    </span>
                  )}
                  <ArrowRight size={16} className="text-slate-600" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Certificate Details */}
        {currentSelectedCert && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6 h-fit sticky top-6">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase block truncate max-w-[240px]">
                  FP: {currentSelectedCert.fingerprint_sha256}
                </span>
                <h3 className="text-lg font-bold text-slate-100 mt-1">X.509 Certificate</h3>
              </div>
              <button
                onClick={() => setSelectedCert(null)}
                className="text-slate-500 hover:text-slate-300 p-1"
              >
                <X size={18} />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs divide-y divide-slate-800/60">
              <div className="pt-2">
                <span className="text-slate-500 block mb-1">Subject:</span>
                <span className="text-slate-200 font-semibold">{currentSelectedCert.subject}</span>
              </div>
              <div className="pt-2">
                <span className="text-slate-500 block mb-1">Issuer:</span>
                <span className="text-slate-200">{currentSelectedCert.issuer}</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Public Key:</span>
                <span className="text-slate-200">{currentSelectedCert.public_key_algorithm} ({currentSelectedCert.public_key_size_bits} bit)</span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Weak Key:</span>
                <span className={currentSelectedCert.weak_key ? 'text-red-400' : 'text-emerald-400'}>
                  {currentSelectedCert.weak_key ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="pt-2 flex justify-between">
                <span className="text-slate-500">Signature:</span>
                <span className="text-slate-200">{currentSelectedCert.signature_algorithm || 'Unknown'}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
