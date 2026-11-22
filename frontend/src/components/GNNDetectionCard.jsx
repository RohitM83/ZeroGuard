import { useEffect, useState } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

const API_URL = 'http://127.0.0.1:8000';

export default function GNNDetectionCard() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function analyzeNetwork() {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_URL}/api/gnn/analyze`);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'GNN analysis failed');
      }

      setResult(data);
    } catch (err) {
      console.error('GNN analysis error:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    analyzeNetwork();

    const interval = setInterval(analyzeNetwork, 10000);

    return () => clearInterval(interval);
  }, []);

  const score = result?.anomaly_score ?? 0;

  const status =
    result?.status?.toUpperCase() || 'UNKNOWN';

  const statusClass =
    status === 'HIGH'
      ? 'text-red-400'
      : status === 'SUSPICIOUS'
      ? 'text-yellow-400'
      : 'text-emerald-400';

  const barClass =
    status === 'HIGH'
      ? 'bg-red-500'
      : status === 'SUSPICIOUS'
      ? 'bg-yellow-500'
      : 'bg-emerald-500';

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      <div className="mb-5 flex items-center justify-between">

        <div className="flex items-center gap-3">

          <div className="rounded-lg bg-red-500/10 p-2">
            <ShieldAlert
              size={18}
              className="text-red-400"
            />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200">
              GNN Threat Detection
            </h3>

            <p className="text-xs text-slate-500">
              ZeroGuard anomaly analysis
            </p>
          </div>

        </div>

        <button
          onClick={analyzeNetwork}
          disabled={loading}
          className="rounded-lg border border-slate-800 bg-slate-950 p-2 text-slate-400 hover:bg-slate-800 hover:text-white disabled:opacity-50"
        >
          <RefreshCw
            size={14}
            className={loading ? 'animate-spin' : ''}
          />
        </button>

      </div>

      {error ? (

        <div className="rounded-lg border border-red-800/50 bg-red-950/20 p-4">
          <p className="text-sm font-medium text-red-400">
            GNN unavailable
          </p>

          <p className="mt-1 text-xs text-red-500">
            {error}
          </p>
        </div>

      ) : loading ? (

        <div className="py-8 text-center text-sm text-slate-500">
          Running GNN analysis...
        </div>

      ) : (

        <div>

          <div className="mb-4 flex items-end justify-between">

            <div>
              <p className="text-xs text-slate-500">
                Anomaly Score
              </p>

              <p className="mt-1 text-4xl font-bold text-white">
                {score}
                <span className="text-lg text-slate-500">
                  /100
                </span>
              </p>
            </div>

            <div className={`text-sm font-bold ${statusClass}`}>
              {status}
            </div>

          </div>

          <div className="h-2 overflow-hidden rounded-full bg-slate-800">

            <div
              className={`h-full rounded-full transition-all duration-700 ${barClass}`}
              style={{
                width: `${Math.min(score, 100)}%`,
              }}
            />

          </div>

          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">

            <Feature
              label="Connections"
              value={result.features?.[0]}
            />

            <Feature
              label="Sources"
              value={result.features?.[1]}
            />

            <Feature
              label="Destinations"
              value={result.features?.[2]}
            />

            <Feature
              label="Ports"
              value={result.features?.[3]}
            />

          </div>

          <p className="mt-4 text-xs leading-relaxed text-slate-500">
            The GNN analyzes current network behavior against the
            learned baseline. A high anomaly score indicates behavior
            that requires investigation; it is not by itself proof of
            a cyberattack.
          </p>

        </div>

      )}

    </div>
  );
}

function Feature({ label, value }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <p className="text-xs text-slate-600">
        {label}
      </p>

      <p className="mt-1 font-mono text-sm text-slate-300">
        {value ?? '-'}
      </p>
    </div>
  );
}