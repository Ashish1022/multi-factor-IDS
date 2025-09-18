"use client";

import useSWR from "swr";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function StatusPage() {
  const { data } = useSWR<{ components: Record<string, string> }>("http://localhost:5001/api/status", fetcher, { refreshInterval: 5000 });

  return (
    <div className="p-4 grid gap-4 grid-cols-1 md:grid-cols-2">
      {data?.components ? (
        Object.entries(data.components).map(([name, state]) => (
          <Card key={name}>
            <CardHeader>
              <CardTitle>{name}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className={`font-semibold ${state === "active" ? "text-green-600" : "text-red-600"}`}>
                {state}
              </p>
            </CardContent>
          </Card>
        ))
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
}
