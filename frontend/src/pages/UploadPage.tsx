import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, File, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { uploadPcap } from '../lib/api';
import { useCapture } from '../context/CaptureContext';

export const UploadPage = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const { refreshCaptures, setActiveCaptureId } = useCapture();
  const navigate = useNavigate();

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (f: File) => {
    setError(null);
    const ext = f.name.toLowerCase().split('.').pop();
    if (!['pcap', 'pcapng', 'cap'].includes(ext || '')) {
      setError('Invalid file format. Only .pcap, .pcapng, and .cap files are accepted.');
      return;
    }
    setFile(f);
  };

  const handleUpload = async () => {
    if (!file) return;

    try {
      setUploading(true);
      setError(null);

      const res = await uploadPcap(file);
      await refreshCaptures();
      if (res.capture_id) {
        setActiveCaptureId(res.capture_id);
      }
      navigate('/');
    } catch (err: any) {
      console.error(err);
      setError(err?.response?.data?.detail || 'Failed to analyze PCAP capture. Ensure backend is running.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100 tracking-tight">Ingest Network Capture</h2>
        <p className="text-sm text-slate-400 mt-1">Upload PCAP / PCAPNG packet captures for passive email TLS security forensics.</p>
      </div>

      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleFileDrop}
        className="border-2 border-dashed border-slate-700 bg-slate-900/40 hover:bg-slate-900/70 hover:border-amber-500/50 rounded-xl p-12 text-center transition-all cursor-pointer flex flex-col items-center justify-center min-h-[300px]"
        onClick={() => document.getElementById('pcap-input')?.click()}
      >
        <input
          id="pcap-input"
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4 text-amber-400">
          <UploadCloud size={32} />
        </div>

        <h3 className="text-lg font-semibold text-slate-200">Drag and drop packet capture</h3>
        <p className="text-sm text-slate-500 mt-1">Supports standard PCAP and PCAPNG file formats up to 100 MB</p>

        {file && (
          <div className="mt-6 flex items-center gap-3 bg-slate-800/80 px-4 py-2.5 rounded-lg border border-slate-700 text-left">
            <File className="text-amber-400 shrink-0" size={20} />
            <div>
              <div className="text-sm font-medium text-slate-200">{file.name}</div>
              <div className="text-xs text-slate-500">{(file.size / (1024 * 1024)).toFixed(2)} MB</div>
            </div>
            <CheckCircle2 className="text-emerald-400 ml-4 shrink-0" size={18} />
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-950/50 border border-red-800/80 text-red-200 px-4 py-3 rounded-lg flex items-center gap-3 text-sm">
          <AlertTriangle size={18} className="text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex justify-end gap-4">
        {file && (
          <button
            onClick={() => setFile(null)}
            disabled={uploading}
            className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200"
          >
            Clear
          </button>
        )}
        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className="bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:hover:bg-amber-500 text-slate-950 font-bold px-6 py-2.5 rounded-lg transition-colors flex items-center gap-2 text-sm shadow-lg shadow-amber-500/10"
        >
          {uploading ? (
            <>
              <Loader2 className="animate-spin" size={18} />
              <span>Analyzing Capture (M1-M11)...</span>
            </>
          ) : (
            <span>Run Pipeline Analysis</span>
          )}
        </button>
      </div>
    </div>
  );
};
