import { useEffect, useState } from "react";
import {
  ShieldOff,
  RefreshCw,
} from "lucide-react";

import EmptyState from "../ui/EmptyState";

const API_URL = "http://127.0.0.1:8000";


export default function ThreatSeverityChart() {

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);


  async function loadThreatSeverity() {

    try {

      setLoading(true);
      setError(null);

      const response = await fetch(
        `${API_URL}/api/threats/severity`
      );

      if (!response.ok) {

        throw new Error(
          `Failed to load threat severity: HTTP ${response.status}`
        );
      }

      const result = await response.json();

      console.log(
        "Threat severity data:",
        result
      );

      setData(result);

    } catch (error) {

      console.error(
        "Failed to load threat severity:",
        error
      );

      setData(null);

      setError(
        error.message
      );

    } finally {

      setLoading(false);
    }
  }


  useEffect(() => {

    loadThreatSeverity();

    const interval = setInterval(
      loadThreatSeverity,
      10000
    );

    return () => {
      clearInterval(interval);
    };

  }, []);


  const bars = [

    {
      label: "Critical",
      color: "bg-red-500",
      count: data?.critical ?? 0,
    },

    {
      label: "High",
      color: "bg-orange-500",
      count: data?.high ?? 0,
    },

    {
      label: "Medium",
      color: "bg-yellow-500",
      count: data?.medium ?? 0,
    },

    {
      label: "Low",
      color: "bg-blue-500",
      count: data?.low ?? 0,
    },

  ];


  const total = bars.reduce(
    (sum, bar) =>
      sum + bar.count,
    0
  );


  const hasData = total > 0;


  return (

    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      {/* HEADER */}

      <div className="mb-5 flex items-center justify-between">

        <div>

          <h3 className="text-sm font-semibold text-slate-200">
            Threat Severity Breakdown
          </h3>

          <p className="mt-1 text-xs text-slate-500">
            Distribution of detected threats
          </p>

        </div>


        <div className="flex items-center gap-2">

          {loading && (

            <RefreshCw
              size={13}
              className="animate-spin text-slate-500"
            />

          )}

          <span className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-500">
            Live data
          </span>

        </div>

      </div>


      {/* ERROR */}

      {error && !loading && (

        <div className="mb-4 rounded-lg border border-red-900/50 bg-red-950/20 px-3 py-2">

          <p className="text-xs text-red-400">
            Unable to load severity data.
          </p>

          <p className="mt-1 text-xs text-slate-600">
            {error}
          </p>

        </div>

      )}


      {/* NO DATA */}

      {!hasData && !loading ? (

        <EmptyState
          icon={ShieldOff}
          title="No threat data available"
          description="Severity breakdown will appear when threats are detected."
        />

      ) : loading ? (

        <div className="flex h-[180px] items-center justify-center gap-2 text-sm text-slate-500">

          <RefreshCw
            size={16}
            className="animate-spin"
          />

          Loading threat data...

        </div>

      ) : (

        <div className="space-y-4">

          {bars.map((bar) => (

            <div
              key={bar.label}
            >

              <div className="mb-1.5 flex justify-between text-xs">

                <span className="text-slate-400">
                  {bar.label}
                </span>

                <span className="font-medium text-slate-300">
                  {bar.count}
                </span>

              </div>


              <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">

                <div
                  className={`h-full rounded-full ${bar.color} transition-all duration-700`}
                  style={{
                    width:
                      total > 0
                        ? `${(bar.count / total) * 100}%`
                        : "0%",
                  }}
                />

              </div>

            </div>

          ))}


          {/* TOTAL */}

          <div className="mt-5 flex items-center justify-between border-t border-slate-800 pt-4">

            <span className="text-xs text-slate-500">
              Total threats
            </span>

            <span className="text-sm font-semibold text-slate-200">
              {total}
            </span>

          </div>

        </div>

      )}

    </div>

  );
}