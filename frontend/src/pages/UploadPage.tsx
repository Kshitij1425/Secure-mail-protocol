import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, File as FileIcon, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { errorMessage, uploadPcap } from '../lib/api';
import { useCapture } from '../context/CaptureContext';

const MAX_MB = 100;
const EXTENSIONS = ['pcap', 'pcapng', 'cap'];

export const UploadPage = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const { refreshCaptures, setActiveCaptureId } = useCapture();
  const navigate = useNavigate();

  const choose = (f: File | undefined) => {
    setError(null);
    if (!f) return;
    const ext = f.name.toLowerCase().split('.').pop() ?? '';
    if (!EXTENSIONS.includes(ext)) return setError('Only .pcap, .pcapng and .cap files are accepted.');
    if (f.size === 0) return setError('The selected file is empty.');
    if (f.size > MAX_MB * 1024 * 1024) return setError(`File exceeds the ${MAX_MB} MB upload limit.`);
    setFile(f);
  };

  const onDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    choose(e.dataTransfer.files?.[0]);
  };

  const upload = async () => {
    if (!file) return;
    setUploading(true);
    setProgress(0);
    setError(null);
    try {
      const res = await uploadPcap(file, setProgress);
      await refreshCaptures();
      setActiveCaptureId(res.capture_id);
      navigate('/');
    } catch (err) {
      await refreshCaptures();
      setError(errorMessage(err, 'Analysis failed.'));
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Analyze a Network Capture</h2>
        <p className="text-sm text-slate-400 mt-1">PCAP / PCAPNG captures are analyzed passively; nothing is sent to any mail server.</p>
      </div>

      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
        role="button"
        tabIndex={0}
        aria-label="Choose a PCAP capture file"
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click(); } }}
        onClick={() => input.current?.click()}
        className="border-2 border-dashed border-slate-700 bg-slate-900/40 hover:bg-slate-900/70 hover:border-amber-500/50 rounded-xl p-12 text-center transition-all cursor-pointer flex flex-col items-center justify-center min-h-[300px]"
      >
        <input ref={input} id="pcap-input" type="file" accept=".pcap,.pcapng,.cap" className="hidden"
          onChange={(e) => { choose(e.target.files?.[0]); e.target.value = ''; }} />
        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4 text-amber-400"><UploadCloud size={32} /></div>
        <h3 className="text-lg font-semibold text-slate-200">Drop a capture here or click to browse</h3>
        <p className="text-sm text-slate-500 mt-1">PCAP and PCAPNG, up to {MAX_MB} MB</p>
        {file && (
          <div className="mt-6 flex items-center gap-3 bg-slate-800/80 px-4 py-2.5 rounded-lg border border-slate-700 text-left">
            <FileIcon className="text-amber-400 shrink-0" size={20} />
            <div className="min-w-0">
              <div className="text-sm font-medium text-slate-200 break-all">{file.name}</div>
              <div className="text-xs text-slate-500">{(file.size / (1024 * 1024)).toFixed(2)} MB</div>
            </div>
            <CheckCircle2 className="text-emerald-400 ml-4 shrink-0" size={18} />
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="bg-red-950/50 border border-red-800/80 text-red-200 px-4 py-3 rounded-lg flex items-center gap-3 text-sm">
          <AlertTriangle size={18} className="text-red-400 shrink-0" /><span>{error}</span>
        </div>
      )}

      <div className="flex justify-end items-center gap-4">
        {uploading && <span className="text-xs text-slate-400">{progress < 100 ? `Uploading ${progress}%` : 'Analyzing capture…'}</span>}
        {file && !uploading && (
          <button type="button" onClick={() => setFile(null)} className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200">Clear</button>
        )}
        <button type="button" onClick={() => void upload()} disabled={!file || uploading}
          className="bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:hover:bg-amber-500 text-slate-950 font-bold px-6 py-2.5 rounded-lg transition-colors flex items-center gap-2 text-sm">
          {uploading ? <><Loader2 className="animate-spin" size={18} /><span>Analyzing…</span></> : <span>Run analysis</span>}
        </button>
      </div>
    </div>
  );
};
