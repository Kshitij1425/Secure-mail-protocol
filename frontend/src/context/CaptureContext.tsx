import { createContext, useState, useEffect, useCallback, useContext } from 'react';
import type { ReactNode } from 'react';
import { getCaptures, errorMessage } from '../lib/api';
import type { CaptureSummary } from '../types/api';

export interface CaptureContextType {
  activeCaptureId: string | null;
  setActiveCaptureId: (id: string | null) => void;
  captures: CaptureSummary[];
  activeCapture: CaptureSummary | null;
  loading: boolean;
  error: string | null;
  refreshCaptures: () => Promise<CaptureSummary[]>;
}

const STORAGE_KEY = 'sms.activeCapture';
const CaptureContext = createContext<CaptureContextType | undefined>(undefined);

const readStored = (): string | null => {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};

export const CaptureProvider = ({ children }: { children: ReactNode }) => {
  const [activeCaptureId, setActive] = useState<string | null>(readStored);
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // The stored id is only trusted after it has been checked against the server's list.
  const [validated, setValidated] = useState(false);

  const setActiveCaptureId = useCallback((id: string | null) => {
    setActive(id);
    try {
      if (id) window.localStorage.setItem(STORAGE_KEY, id);
      else window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* storage unavailable: selection just won't persist */
    }
  }, []);

  // Fetch without a synchronous state change (initial render already has loading=true).
  const load = useCallback(async () => {
    try {
      const data = await getCaptures();
      setCaptures(data);
      setError(null);
      setValidated(true);
      setActive((prev) => {
        const keep = prev && data.some((c) => c.capture_id === prev) ? prev : null;
        const next = keep ?? data.find((c) => c.analysis_status === 'completed')?.capture_id ?? data[0]?.capture_id ?? null;
        try {
          if (next) window.localStorage.setItem(STORAGE_KEY, next);
        } catch { /* ignore */ }
        return next;
      });
      return data;
    } catch (e) {
      setError(errorMessage(e, 'Failed to load captures'));
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  /** User-triggered refresh (event handlers): shows the loading state, then reloads. */
  const refreshCaptures = useCallback(async () => {
    setLoading(true);
    return load();
  }, [load]);

  useEffect(() => {
    // Mount-time data fetch; every state update in load() happens after the awaited request.
    // oxlint-disable-next-line react/set-state-in-effect
    void load();
  }, [load]);

  const exposedId = validated ? activeCaptureId : null;
  const activeCapture = captures.find((c) => c.capture_id === exposedId) ?? null;

  return (
    <CaptureContext.Provider value={{ activeCaptureId: exposedId, setActiveCaptureId, captures, activeCapture, loading, error, refreshCaptures }}>
      {children}
    </CaptureContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useCapture = () => {
  const ctx = useContext(CaptureContext);
  if (!ctx) throw new Error('useCapture must be used within CaptureProvider');
  return ctx;
};
