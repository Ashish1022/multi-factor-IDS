import sys
import signal
import threading
import asyncio
import json

from pathlib import Path
sys.path.append(str(Path(__file__).parent))

# IDS components
from network_monitor.packet_analyzer import NetworkMonitor
from host_monitor.system_monitor import HostMonitor
from baseline_engine.behavior_analyzer import BaselineEngine
from correlation_engine.event_correlator import CorrelationEngine
from alert_manager.alert_handler import AlertManager
from api.server import APIServer

# Utilities
from utils.config_loader import ConfigLoader
from utils.logger import setup_logging

# WebSocket
import websockets


class WebSocketServer:
    """WebSocket server for broadcasting IDS alerts"""

    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.loop = asyncio.new_event_loop()

    async def handler(self, websocket):
        self.clients.add(websocket)
        try:
            async for _ in websocket:
                pass  # clients don’t send data
        finally:
            self.clients.remove(websocket)

    async def broadcast(self, message: str):
        if self.clients:
            await asyncio.gather(
                *[client.send(message) for client in self.clients],
                return_exceptions=True
            )

    def start(self):
        def run():
            asyncio.set_event_loop(self.loop)
            server = websockets.serve(self.handler, self.host, self.port)
            self.loop.run_until_complete(server)
            print(f"✅ WebSocket running on ws://{self.host}:{self.port}")
            self.loop.run_forever()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

    def send(self, message: str):
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self.loop)


class MultiFactorIDS:
    def __init__(self, config_path="config/config.yaml"):
        self.config = ConfigLoader(config_path)
        self.logger = setup_logging(self.config.get("global.log_level", "INFO"))

        self.shutdown_event = threading.Event()
        self.threads = []

        # Components
        self.alert_manager = None
        self.network_monitor = None
        self.host_monitor = None
        self.baseline_engine = None
        self.correlation_engine = None
        self.api_server = None

        # WebSocket
        self.ws_server = WebSocketServer()

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()

    def initialize_components(self):
        self.logger.info("Initializing IDS components...")

        try:
            self.alert_manager = AlertManager(
                config=self.config.get("alerts", {}),
                shutdown_event=self.shutdown_event,
            )

            # Wrap callback to also push alerts to WS
            def alert_callback(alert):
                self.alert_manager.handle_alert(alert)
                try:
                    self.ws_server.send(json.dumps(alert, default=str))
                except Exception as e:
                    self.logger.error(f"WebSocket send failed: {e}")

            self.network_monitor = NetworkMonitor(
                config=self.config.get("network", {}),
                alert_callback=alert_callback,
                shutdown_event=self.shutdown_event,
            )

            self.host_monitor = HostMonitor(
                config=self.config.get("host", {}),
                alert_callback=alert_callback,
                shutdown_event=self.shutdown_event,
            )

            self.baseline_engine = BaselineEngine(
                config=self.config.get("baseline", {}),
                data_callback=self._baseline_data_callback,
                shutdown_event=self.shutdown_event,
            )

            self.correlation_engine = CorrelationEngine(
                config=self.config.get("correlation", {}),
                alert_callback=alert_callback,
                shutdown_event=self.shutdown_event,
            )

            self.api_server = APIServer(
                config=self.config.get("api", {}),
                ids_components={
                    "network_monitor": self.network_monitor,
                    "host_monitor": self.host_monitor,
                    "baseline_engine": self.baseline_engine,
                    "correlation_engine": self.correlation_engine,
                    "alert_manager": self.alert_manager,
                },
            )

            self.logger.info("✅ All components initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise

    def _baseline_data_callback(self, data):
        if self.correlation_engine:
            self.correlation_engine.process_baseline_data(data)

    def start(self):
        self.logger.info("🚀 Starting Multi-Factor IDS...")
        try:
            self.initialize_components()
            self.ws_server.start()

            components = [
                ("Network Monitor", self.network_monitor.start),
                ("Host Monitor", self.host_monitor.start),
                ("Baseline Engine", self.baseline_engine.start),
                ("Correlation Engine", self.correlation_engine.start),
                ("Alert Manager", self.alert_manager.start),
            ]

            for name, start_fn in components:
                thread = threading.Thread(target=start_fn, name=name, daemon=True)
                thread.start()
                self.threads.append(thread)
                self.logger.info(f"Started {name}")

            # API server thread
            api_thread = threading.Thread(
                target=self.api_server.start, name="API Server", daemon=True
            )
            api_thread.start()
            self.threads.append(api_thread)

            self.logger.info("✅ Multi-Factor IDS running")
            self.logger.info(
                f"📊 API Server: http://localhost:{self.config.get('api.port', 5001)}"
            )
            self.logger.info(f"📡 WebSocket: ws://localhost:8765")

            self.shutdown_event.wait()

        except Exception as e:
            self.logger.error(f"Failed to start IDS: {e}")
            self.shutdown()
            raise

    def shutdown(self):
        self.logger.info("Shutting down IDS...")
        self.shutdown_event.set()

        for thread in self.threads:
            if thread.is_alive():
                self.logger.debug(f"Waiting for {thread.name}...")
                thread.join(timeout=10)
                if thread.is_alive():
                    self.logger.warning(f"{thread.name} did not exit cleanly")

        self.logger.info("✅ Shutdown complete")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Multi-Factor Intrusion Detection System")
    parser.add_argument("--config", default="config/config.yaml", help="Config file")
    args = parser.parse_args()

    ids = MultiFactorIDS(config_path=args.config)
    ids.start()


if __name__ == "__main__":
    main()
