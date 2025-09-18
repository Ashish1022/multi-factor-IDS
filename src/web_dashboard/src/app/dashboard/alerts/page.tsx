"use client";

import useSWR from "swr";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function AlertsPage() {
  const { data } = useSWR("http://localhost:5001/api/alerts?limit=50", fetcher, { refreshInterval: 5000 });

  return (
    <div className="p-4">
      <h1 className="text-xl font-bold mb-4">Active Alerts</h1>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Component</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Timestamp</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data?.alerts?.map((alert: any) => (
            <TableRow key={alert.id}>
              <TableCell>{alert.id}</TableCell>
              <TableCell>{alert.component}</TableCell>
              <TableCell>{alert.severity}</TableCell>
              <TableCell>{alert.status}</TableCell>
              <TableCell>{alert.timestamp}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
