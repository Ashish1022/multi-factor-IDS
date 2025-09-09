import sys
import signal 
import asyncio
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any

sys.path.append(str(Path(__file__).parent))

from network_monitor.packet_analyzer import NetworkMonitor
from host_monitor.system_monitor import HostMonitor
from baseline_engine.behavior_analyzer import BaselineEngine
from correlation_engine.event_correlator import CorrelationEngine
from alert_manager.alert_handler import AlertManager
from web_dashboard.app import create_app
from api.server import APIServer
from utils.config_loader import ConfigLoader
from utils.logger import setup_logging

class MultiFactorIDS:
    def __init__(self, config_path: str = 'config/config.yaml'):
        self.config = ConfigLoader(config_path)
        self.logger = setup_logging(self.config.get('global.log_level', 'INFO'))
        
        self.network_monitor = None
        self.host_monitor = None
        self.baseline_engine = None
        self.correlation_engine = None
        self.alert_manager = None
        self.web_app = None
        self.api_server = None
        
        self.threads: List[threading.Thread] = []
        self.shutdown_event = threading.Event()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self.shutdown()
        
    def initialize_components(self):
        self.logger.info('Initializing IDS components...')
        
        try:
            self.alert_manager = AlertManager(
                config=self.config.set('alerts', {}),
                shutdown_event=self.shutdown_event
            )
            
            self.network_monitor = NetworkMonitor(
                config=self.config.get('network', {}),
                alert_callback=self.alert_manager.handle_alert,
                shutdown_event=self.shutdown_event
            )
            
            self.host_monitor = HostMonitor(
                config=self.config.get('host', {}),
                alert_callback=self.alert_manager.handle_alert,
                shutdown_event=self.shutdown_event
            )
            
            self.baseline_engine = BaselineEngine(
                config=self.config.get('baseline', {}),
                data_callback=self._baseline_data_callback,
                shutdown_event=self.shutdown_event
            )
            
            self.correlation_engine = CorrelationEngine(
                config=self.config.get('correlation', {}),
                alert_callback=self.alert_manager.handle_alert,
                shutdown_event=self.shutdown_event
            )
            
            self.web_app = create_app(self.config.get('dashboard', {}))
            
            self.api_server = APIServer(
                config=self.config.get('api', {}),
                ids_components={
                    'network_monitor': self.network_monitor,
                    'host_monitor': self.host_monitor,
                    'baseline_engine': self.baseline_engine,
                    'correlation_engine': self.correlation_engine,
                    'alert_manager': self.alert_manager
                }
            )
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _baseline_data_callback(self, data: Dict[str, Any]):
        """Callback for baseline engine data"""
        if self.correlation_engine:
            self.correlation_engine.process_baseline_data(data)
            
    def start(self):
        """Start all IDS components"""
        self.logger.info("Starting Multi-Factor IDS...")
        
        try:
            self.initialize_components()
            
            components = [
                ('Network Monitor', self.network_monitor.start),
                ('Host Monitor', self.host_monitor.start),
                ('Baseline Engine', self.baseline_engine.start),
                ('Correlation Engine', self.correlation_engine.start),
                ('Alert Manager', self.alert_manager.start)
            ]
            
            for name, start_method in components:
                thread = threading.Thread(
                    target=start_method,
                    name=name,
                    daemon=True
                )
                thread.start()
                self.threads.append(thread)
                self.logger.info(f"Started {name}")
            
            dashboard_thread = threading.Thread(
                target=lambda: self.web_app.run(
                    host=self.config.get('dashboard.host', '0.0.0.0'),
                    port=self.config.get('dashboard.port', 5000),
                    debug=False
                ),
                name='Web Dashboard',
                daemon=True
            )
            dashboard_thread.start()
            self.threads.append(dashboard_thread)
            
            api_thread = threading.Thread(
                target=self.api_server.start,
                name='API Server',
                daemon=True
            )
            api_thread.start()
            self.threads.append(api_thread)
            
            self.logger.info("Multi-Factor IDS started successfully")
            self.logger.info(f"Web Dashboard: http://localhost:{self.config.get('dashboard.port', 5000)}")
            self.logger.info(f"API Server: http://localhost:{self.config.get('api.port', 5001)}")
            
            self.shutdown_event.wait()
            
        except Exception as e:
            self.logger.error(f"Failed to start IDS: {e}")
            self.shutdown()
            raise
    
    def shutdown(self):
        """Shutdown all components gracefully"""
        self.logger.info("Shutting down Multi-Factor IDS...")
        
        self.shutdown_event.set()
        
        for thread in self.threads:
            if thread.is_alive():
                self.logger.debug(f"Waiting for {thread.name} to shutdown...")
                thread.join(timeout=10)
                if thread.is_alive():
                    self.logger.warning(f"{thread.name} did not shutdown gracefully")
        
        self.logger.info("Multi-Factor IDS shutdown complete")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Multi-Factor Intrusion Detection System')
    parser.add_argument(
        '--config', 
        default='config/config.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='Run as daemon'
    )
    
    args = parser.parse_args()
    
    try:
        ids = MultiFactorIDS(config_path=args.config)
        ids.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()