import { useCallback, useEffect, useState } from 'react';
import { errorMessage } from '../lib/api';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/** Runs ``fn`` whenever ``key`` changes; ignores stale responses. ``key === null`` means idle. */
export function useAsync<T>(fn: () => Promise<T>, key: string | null): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (key === null) {
      setData(null);
      setError(null);
      setLoading(false);
      return;
    }
    let live = true;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => live && setData(d))
      .catch((e) => live && (setError(errorMessage(e)), setData(null)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, reload };
}
