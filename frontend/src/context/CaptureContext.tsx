import { createContext, useState, useEffect, useCallback, useContext } from 'react';
import type { ReactNode } from 'react';
import { getCaptures } from '../lib/api';
import type { CaptureSummary } from '../types/api';

export interface CaptureContextType {
  activeCaptureId: string | null;
  setActiveCaptureId: (id: string | null) => void;
  captures: CaptureSummary[];
  loading: boolean;
  refreshCaptures: () => Promise<void>;
}

const CaptureContext = createContext<CaptureContextType | undefined>(undefined);

export const CaptureProvider = ({ children }: { children: ReactNode }) => {
  const [activeCaptureId, setActiveCaptureId] = useState<string | null>(null);
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const refreshCaptures = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getCaptures();
      setCaptures(data);
      setActiveCaptureId((prev) => prev ?? (data.length > 0 ? data[0].capture_id : null));
    } catch (e) {
      console.error('Failed to load captures', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshCaptures();
  }, [refreshCaptures]);

  return (
    <CaptureContext.Provider value={{ activeCaptureId, setActiveCaptureId, captures, loading, refreshCaptures }}>
      {children}
    </CaptureContext.Provider>
  );
};

export const useCapture = () => {
  const ctx = useContext(CaptureContext);
  if (!ctx) throw new Error('useCapture must be used within CaptureProvider');
  return ctx;
};
