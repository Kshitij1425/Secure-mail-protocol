import { useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Detail selection lives in the URL (``?id=...``) so that back/forward, refresh and
 * deep links all work. Escape closes the panel.
 */
export const useDetailPanel = () => {
  const [params, setParams] = useSearchParams();
  const selectedId = params.get('id');

  const open = useCallback((id: string | number) => {
    setParams((p) => {
      const next = new URLSearchParams(p);
      next.set('id', String(id));
      return next;
    });
  }, [setParams]);

  const close = useCallback(() => {
    setParams((p) => {
      const next = new URLSearchParams(p);
      next.delete('id');
      return next;
    });
  }, [setParams]);

  useEffect(() => {
    if (!selectedId) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedId, close]);

  return { selectedId, open, close };
};
