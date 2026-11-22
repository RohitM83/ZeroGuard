import { useEffect, useState } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import EmptyState from '../ui/EmptyState';

import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';

const API_URL = 'http://127.0.0.1:8000';


const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs shadow-lg">
        <p className="text-slate-400">{label}</p>

        <p className="font-semibold text-blue-400">
          {payload[0].value} events
        </p>
      </div>
    );
  }

  return null;
};


export default function NetworkActivityChart() {
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);


  async function loadNetworkEvents() {
    try {
      setLoading(true);

      const response = await fetch(
        `${API_URL}/api/network-events`
      );

      if (!response.ok) {
        throw new Error(
          `Failed to load events: ${response.status}`
        );
      }

      const events = await response.json();

      /*
        Group events according to their timestamp.

        Example:

        13:30 → 15 events
        13:31 → 22 events
        13:32 → 10 events
      */

      const groupedEvents = {};

      events.forEach((event) => {
        if (!event.timestamp) return;

        const date = new Date(event.timestamp);

        if (Number.isNaN(date.getTime())) return;

        const time = date.toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        });

        groupedEvents[time] =
          (groupedEvents[time] || 0) + 1;
      });


      const formattedData = Object.entries(groupedEvents)
        .map(([time, events]) => ({
          time,
          events,
        }))
        .slice(-20);


      setChartData(formattedData);

    } catch (error) {
      console.error(
        'Failed to load network chart data:',
        error
      );

      setChartData([]);

    } finally {
      setLoading(false);
    }
  }


  useEffect(() => {
    loadNetworkEvents();

    // Refresh chart every 10 seconds
    const interval = setInterval(
      loadNetworkEvents,
      10000
    );

    return () => clearInterval(interval);

  }, []);


  const hasData =
    Array.isArray(chartData) &&
    chartData.length > 0;


  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">

      <div className="mb-4 flex items-center justify-between">

        <h3 className="text-sm font-semibold text-slate-200">
          Network Event Volume
        </h3>

        <div className="flex items-center gap-2">

          {loading && (
            <RefreshCw
              size={13}
              className="animate-spin text-slate-500"
            />
          )}

          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-500">
            Latest 100 events
          </span>

        </div>

      </div>


      {!hasData && !loading ? (

        <EmptyState
          icon={Activity}
          title="No network activity recorded"
          description="Network events will appear here when the backend provides data."
        />

      ) : loading ? (

        <div className="flex h-[180px] items-center justify-center gap-2 text-sm text-slate-500">
          <RefreshCw
            size={16}
            className="animate-spin"
          />

          Loading network activity...

        </div>

      ) : (

        <ResponsiveContainer
          width="100%"
          height={180}
        >

          <LineChart
            data={chartData}
            margin={{
              top: 4,
              right: 4,
              bottom: 0,
              left: -20,
            }}
          >

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#1e293b"
            />

            <XAxis
              dataKey="time"
              tick={{
                fontSize: 11,
                fill: '#64748b',
              }}
              axisLine={false}
              tickLine={false}
            />

            <YAxis
              domain={[0, 'auto']}
              allowDecimals={false}
              tick={{
                fontSize: 11,
                fill: '#64748b',
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              content={<CustomTooltip />}
            />

            <Line
              type="monotone"
              dataKey="events"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={false}
              activeDot={{
                r: 4,
                fill: '#3b82f6',
              }}
            />

          </LineChart>

        </ResponsiveContainer>

      )}

    </div>
  );
}