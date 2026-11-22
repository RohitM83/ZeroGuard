import { useState, useEffect, useCallback } from 'react';
import { getStatus } from '../services/api';

/**
 * Polls GET /api/status at a regular interval.
 * Returns { data, error, loading, refetch }.
 */
export function useApiStatus(pollInterval = 15000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    const result = await getStatus();
    if (result.error) {
      setError(result.error);
      setData(null);
    } else {
      setData(result.data);
      setError(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetch();
    const interval = setInterval(fetch, pollInterval);
    return () => clearInterval(interval);
  }, [fetch, pollInterval]);

  return { data, error, loading, refetch: fetch };
}
