"use client";

import { useEffect, useState } from "react";

interface AlertEvent {
  id?: string;
  timestamp: string;
  alert_type: string;
  severity?: string;
  description?: string;
  source?: string;
}

export default function Dashboard() {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8765"); // Python WS

    ws.onmessage = (event) => {
      const data: AlertEvent = JSON.parse(event.data);
      setAlerts((prev) => [data, ...prev].slice(0, 50)); // keep last 50
    };

    return () => ws.close();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">🛡️ IDS Dashboard</h1>

      <div className="rounded-xl shadow-lg bg-white p-4">
        <h2 className="font-semibold text-lg mb-3">Live Alerts</h2>
        <ul className="space-y-2 max-h-[500px] overflow-y-auto">
          {alerts.map((alert, i) => (
            <li
              key={i}
              className="p-3 border rounded-lg bg-gray-50 text-sm flex flex-col"
            >
              <span className="font-semibold">
                [{alert.severity || "INFO"}] {alert.alert_type}
              </span>
              <span>{alert.description}</span>
              <span className="text-xs text-gray-500">
                {new Date(alert.timestamp).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
