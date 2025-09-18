"use client";

import useSWR from "swr";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Dashboard() {
  const { data: status } = useSWR("http://localhost:5001/api/status", fetcher, { refreshInterval: 5000 });
  const { data: stats } = useSWR("http://localhost:5001/api/statistics", fetcher, { refreshInterval: 10000 });

  return (
    <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3 p-4">
      <Card>
        <CardHeader>
          <CardTitle>System Status</CardTitle>
        </CardHeader>
        <CardContent>
          {status ? (
            <div>
              <p>Status: {status.status}</p>
              <p>Timestamp: {status.timestamp}</p>
              <ul>
                {Object.entries(status.components).map(([name, state]) => (
                  <li key={name}>
                    {name}: <span className="font-semibold">{String(state)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p>Loading...</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Alert Statistics</CardTitle>
        </CardHeader>
        <CardContent>
          {stats?.alerts ? (
            <ul>
              {Object.entries(stats.alerts.severity_counts).map(([sev, count]) => (
                <li key={sev}>
                  {sev}: <span className="font-bold">{String(count)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p>Loading...</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
