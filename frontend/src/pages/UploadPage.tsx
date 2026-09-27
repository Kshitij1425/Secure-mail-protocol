import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileUp } from 'lucide-react';
import { errorMessage, getPolicies, uploadPcap } from '../lib/api';
import { useCapture } from '../context/CaptureContext';
import { useAsync } from '../hooks/useAsync';
import { Alert, Breadcrumbs, PageTitle, Panel } from '../components/ui';

const MAX_MB = 100;
const EXTENSIONS = ['pcap', 'pcapng', 'cap'];

export const UploadPage = () => {
  const [file, setFile] = useState<File | null>(null);
  const [policy, setPolicy] = useState('balanced');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const policies = useAsync(getPolicies, 'policies');
  const { refreshCaptures, setActiveCaptureId } = useCapture();
  const navigate = useNavigate();
  const selected = policies.data?.find((p) => p.id === policy);

  const choose = (f: File | undefined) => {
    setError(null);
    if (!f) return;
    const ext = f.name.toLowerCase().split('.').pop() ?? '';
    if (!EXTENSIONS.includes(ext)) return setError('Choose a .pcap, .pcapng or .cap file.');
    if (f.size === 0) return setError('The selected file is empty.');
    if (f.size > MAX_MB * 1024 * 1024) return setError(`The file is larger than the ${MAX_MB} MB upload limit.`);
    setFile(f);
  };

  const run = async () => {
    if (!file) return;
    setBusy(true);
    setProgress(0);
    setError(null);
    try {
      const res = await uploadPcap(file, policy, setProgress);
      await refreshCaptures();
      setActiveCaptureId(res.capture_id);
      navigate('/');
    } catch (e) {
      await refreshCaptures();
      setError(errorMessage(e, 'The analysis failed.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Breadcrumbs items={[{ label: 'Captures', to: '/captures' }, { label: 'Analyze' }]} />
      <PageTitle title="Analyze a capture" lead="The capture is analysed passively on this machine. No mail server is contacted and no traffic is decrypted." />
      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_24rem] gap-5">
        <Panel title="1. Capture file">
          <div role="button" tabIndex={0} aria-label="Choose a capture file"
            onClick={() => input.current?.click()}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.current?.click(); } }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e: React.DragEvent<HTMLDivElement>) => { e.preventDefault(); choose(e.dataTransfer.files?.[0]); }}
            className="border-2 border-dashed border-line-strong rounded bg-sunken hover:bg-signal-soft cursor-pointer px-6 py-12 flex flex-col items-center gap-2 text-center">
            <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={(e) => { choose(e.target.files?.[0]); e.target.value = ''; }} />
            <FileUp size={28} className="text-signal" aria-hidden="true" />
            <span className="font-medium">Drop a capture here or choose a file</span>
            <span className="text-sm text-ink-3">PCAP or PCAPNG, up to {MAX_MB} MB</span>
            {file && <span className="mt-2 text-sm"><span className="font-mono break-all">{file.name}</span> ({(file.size / 1048576).toFixed(2)} MB)</span>}
          </div>
        </Panel>
        <Panel title="2. Policy profile">
          <fieldset className="space-y-2">
            <legend className="sr-only">Policy profile</legend>
            {(policies.data ?? []).map((p) => (
              <label key={p.id} className="flex items-start gap-2 text-sm">
                <input type="radio" name="policy" value={p.id} checked={policy === p.id} onChange={() => setPolicy(p.id)} className="mt-1" />
                <span><strong>{p.name}</strong><span className="block text-ink-2">{p.description}</span></span>
              </label>
            ))}
            {policies.error && <p className="text-sm text-sev-high">{policies.error}</p>}
          </fieldset>
          {selected && <p className="text-xs text-ink-3 mt-3">Minimum keys: RSA {selected.min_rsa_bits}, EC {selected.min_ec_bits}, DH {selected.min_dh_bits} bits. The profile is recorded in every report.</p>}
        </Panel>
      </div>
      {error && <Alert tone="error" title="The capture was not analysed">{error}</Alert>}
      {busy && (
        <Panel title="3. Progress">
          <div role="status" aria-live="polite" className="space-y-2 text-sm">
            <div className="flex justify-between"><span>{progress < 100 ? 'Uploading the capture' : 'Upload complete; analysing on the server'}</span><span className="tabular-nums">{progress < 100 ? `${progress}%` : ''}</span></div>
            <div className="h-2 bg-line rounded-sm overflow-hidden" aria-hidden="true">
              {progress < 100 ? <div className="h-2 bg-signal" style={{ width: `${progress}%` }} /> : <div className="h-2 w-1/3 bg-signal animate-pulse" />}
            </div>
            {progress >= 100 && <p className="text-xs text-ink-3">TCP reassembly, protocol identification, STARTTLS and TLS parsing, certificate analysis, rules, scoring and the ML stage run in one request; large captures take longer.</p>}
          </div>
        </Panel>
      )}
      <div className="flex items-center justify-end gap-3">
        {file && !busy && <button type="button" className="btn" onClick={() => setFile(null)}>Clear</button>}
        <button type="button" className="btn-primary" disabled={!file || busy} onClick={() => void run()}>Run analysis</button>
      </div>
    </>
  );
};
