# ws_server.py
import asyncio
import websockets
import threading
import json

class WebSocketServer:
    """WebSocket server for broadcasting IDS events"""

    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.loop = asyncio.new_event_loop()
        self.server = None

    async def handler(self, websocket, path):
        self.clients.add(websocket)
        try:
            async for _ in websocket:
                pass  # ignore client messages
        finally:
            self.clients.remove(websocket)

    async def broadcast(self, event: dict):
        """Broadcast an event to all clients"""
        if self.clients:
            message = json.dumps(event, default=str)
            await asyncio.gather(*[client.send(message) for client in self.clients])

    def start(self):
        """Start the WebSocket server in a background thread"""
        def run():
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(
                websockets.serve(self.handler, self.host, self.port)
            )
            print(f"✅ WebSocket running on ws://{self.host}:{self.port}")
            self.loop.run_forever()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
