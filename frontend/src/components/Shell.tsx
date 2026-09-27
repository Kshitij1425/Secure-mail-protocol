import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { useCapture } from '../context/CaptureContext';
import { apiClient } from '../lib/api';
import {  } from './ui';
import { fmtScore, fmtUtc } from '../lib/format';

const pref = (k: string, fallback: string) => {
  try { return window.localStorage.getItem(k) ?? fallback; } catch { return fallback; }
};
const save = (k: string, v: string) => { try { window.localStorage.setItem(k, v); } catch { /* ignore */ } };

/** Accessibility strip (GIGW 3.0 convention): skip link, text size, contrast. */
const UtilityStrip = () => {
  const [text, setText] = useState(() => pref('sms.text', 'md'));
  const [contrast, setContrast] = useState(() => pref('sms.contrast', 'normal'));
  useEffect(() => { document.documentElement.dataset.text = text; save('sms.text', text); }, [text]);
  useEffect(() => { document.documentElement.dataset.contrast = contrast; save('sms.contrast', contrast); }, [contrast]);
  const size = (v: string, label: string, aria: string) => (
    <button type="button" aria-label={aria} aria-pressed={text === v} onClick={() => setText(v)}
      className={`px-1.5 rounded-sm ${text === v ? 'bg-chrome-ink/15 text-chrome-ink' : 'text-chrome-muted hover:text-chrome-ink'}`}>{label}</button>
  );
  return (
    <div className="bg-chrome-2 text-chrome-muted text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-1">
        <a href="#main" className="sr-only focus:not-sr-only focus:text-chrome-ink underline">Skip to main content</a>
        <span className="hidden sm:inline">Passive analysis workstation for stored email traffic captures</span>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1" role="group" aria-label="Text size">
            {size('md', 'A', 'Normal text size')}{size('lg', 'A+', 'Larger text')}{size('xl', 'A++', 'Largest text')}
          </span>
          <button type="button" aria-pressed={contrast === 'high'} onClick={() => setContrast(contrast === 'high' ? 'normal' : 'high')}
            className="hover:text-chrome-ink underline-offset-2 hover:underline">
            {contrast === 'high' ? 'Normal contrast' : 'High contrast'}
          </button>
        </div>
      </div>
    </div>
  );
};

const AppHeader = () => {
  const { captures, activeCaptureId, setActiveCaptureId, activeCapture, refreshCaptures, loading, error } = useCapture();
  return (
    <header className="bg-chrome text-chrome-ink border-b border-chrome-2">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
        <div className="flex items-center gap-3 mr-auto">
          <svg aria-hidden="true" viewBox="0 0 32 32" className="w-8 h-8"><rect width="32" height="32" rx="4" fill="currentColor" opacity=".08" /><path d="M7 10h18v12H7z" fill="none" stroke="currentColor" strokeWidth="2" /><path d="M7 10l9 7 9-7" fill="none" stroke="currentColor" strokeWidth="2" /><circle cx="23" cy="22" r="4" fill="rgb(var(--chrome))" stroke="#7FA8DD" strokeWidth="2" /></svg>
          <div>
            <div className="text-lg font-semibold tracking-wide leading-tight">SecureMailScope</div>
            <div className="text-xs text-chrome-muted leading-tight">Email cryptographic posture analysis</div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm min-w-0 max-w-full">
          <label htmlFor="active-capture" className="text-chrome-muted">Analysis</label>
          <select id="active-capture" value={activeCaptureId ?? ''} onChange={(e) => setActiveCaptureId(e.target.value || null)}
            className="bg-chrome-2 border border-chrome-muted/40 text-chrome-ink rounded px-2 py-1 min-w-0 w-full sm:w-auto max-w-full sm:max-w-[26rem]">
            {captures.length === 0 && <option value="">No analyses yet</option>}
            {captures.map((c) => (
              <option key={c.capture_id} value={c.capture_id}>
                {c.filename} - {c.policy_profile ?? 'balanced'} - {c.analysis_status === 'completed' ? `score ${fmtScore(c.posture_score)}` : c.analysis_status}
              </option>
            ))}
          </select>
          <button type="button" onClick={() => void refreshCaptures()} disabled={loading} aria-label="Reload analysis list"
            className="p-1.5 rounded text-chrome-muted hover:text-chrome-ink disabled:opacity-50"><RefreshCw size={14} className={loading ? 'animate-spin' : ''} /></button>
        </div>
      </div>
      {(error || activeCapture?.analysis_status === 'failed') && (
        <div role="alert" className="px-4 py-1.5 text-xs bg-sev-critical/70 text-white">
          {error ?? `Analysis failed: ${activeCapture?.analysis_error ?? 'unknown error'}`}
        </div>
      )}
    </header>
  );
};

const STEPS: { to: string; label: string; count?: (c: ReturnType<typeof useCapture>['activeCapture']) => number | null }[] = [
  { to: '/captures', label: 'Captures' },
  { to: '/', label: 'Overview' },
  { to: '/findings', label: 'Findings', count: (c) => c?.findings_count ?? null },
  { to: '/sessions', label: 'Sessions', count: (c) => c?.email_session_count ?? null },
  { to: '/certificates', label: 'Certificates' },
  { to: '/timeline', label: 'Timeline' },
  { to: '/anomalies', label: 'Anomalies', count: (c) => c?.anomalies_count ?? null },
  { to: '/reports', label: 'Reports and export' },
];

const SideNav = () => {
  const { activeCapture } = useCapture();
  const item = (to: string, label: ReactNode, end = false) => (
    <NavLink to={to} end={end}
      className={({ isActive }) => `flex items-center gap-2 px-3 py-2 rounded text-sm ${isActive ? 'bg-panel text-ink font-medium border border-line' : 'text-ink-2 hover:bg-panel/60 hover:text-ink border border-transparent'}`}>
      {label}
    </NavLink>
  );
  return (
    <nav aria-label="Workflow" className="w-full lg:w-60 shrink-0 lg:border-r border-b lg:border-b-0 border-line bg-sunken">
      <div className="p-3 space-y-4">
        <div>
          <div className="label px-3 mb-1.5">Investigation workflow</div>
          <ol className="space-y-0.5">
            {STEPS.map((s, i) => {
              const n = s.count?.(activeCapture);
              return (
                <li key={s.to}>
                  {item(s.to, <><span className="w-4 text-right text-ink-3 tabular-nums text-xs" aria-hidden="true">{i + 1}</span><span className="flex-1">{s.label}</span>{n !== null && n !== undefined && <span className="text-xs tabular-nums text-ink-3">{n}</span>}</>, s.to === '/')}
                </li>
              );
            })}
          </ol>
        </div>
        <div>
          <div className="label px-3 mb-1.5">Tools</div>
          <ul className="space-y-0.5">
            <li>{item('/upload', 'Analyse a capture')}</li>
            <li>{item('/compare', 'Compare analyses')}</li>
          </ul>
        </div>
      </div>
    </nav>
  );
};

const Footer = () => {
  const [version, setVersion] = useState<string>('');
  const { activeCapture } = useCapture();
  useEffect(() => {
    apiClient.get<{ version: string }>('/health').then((r) => setVersion(r.data.version)).catch(() => setVersion(''));
  }, []);
  return (
    <footer className="border-t border-line bg-panel text-xs text-ink-3">
      <div className="flex flex-wrap gap-x-6 gap-y-1 px-4 py-3">
        <span>SecureMailScope {version && `v${version}`}</span>
        {activeCapture?.analysis_timestamp && <span>Selected analysis completed {fmtUtc(activeCapture.analysis_timestamp)}</span>}
        <span>Passive analysis of stored captures. No traffic is generated and nothing is decrypted.</span>
        <span className="lg:ml-auto">Independent academic project (SIH 2026, SIH26159). Not affiliated with or endorsed by any government agency.</span>
      </div>
    </footer>
  );
};

export const Shell = ({ children }: { children: ReactNode }) => (
  <div className="min-h-screen flex flex-col">
    <UtilityStrip />
    <AppHeader />
    <div className="flex-1 flex flex-col lg:flex-row min-h-0">
      <SideNav />
      <main id="main" tabIndex={-1} className="flex-1 min-w-0 p-4 lg:p-6 space-y-5 focus:outline-none">{children}</main>
    </div>
    <Footer />
  </div>
);
