import { NextRequest } from "next/server";
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws) => {
  console.log("🔌 Client connected");

  ws.on("message", (msg) => {
    const payload = JSON.parse(msg.toString());

    // If HostMonitor sends data → forward to dashboards
    if (payload.type === "hostMetrics") {
      wss.clients.forEach((client) => {
        if (client.readyState === ws.OPEN) {
          client.send(JSON.stringify(payload));
        }
      });
    }
  });

  ws.on("close", () => console.log("❌ Client disconnected"));
});

export const config = {
  runtime: "nodejs",
};

export async function GET(req: NextRequest) {
  const { socket } = (req as any);

  if (!socket.server.wss) {
    socket.server.wss = wss;
    socket.server.on("upgrade", (request: any, socket: any, head: any) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
      });
    });
  }

  return new Response("WebSocket server running");
}
