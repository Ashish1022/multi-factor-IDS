"use client";

import useSWR from "swr";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function StatsPage() {
  const { data } = useSWR("http://localhost:5001/api/statistics", fetcher, { refreshInterval: 10000 });

  return (
    <div className="p-4 grid gap-4 grid-cols-1 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Alerts per Day</CardTitle>
        </CardHeader>
        <CardContent>
          {data?.alerts?.daily_stats ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={data.alerts.daily_stats}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="count" stroke="#624CF5" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <p>No data</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
