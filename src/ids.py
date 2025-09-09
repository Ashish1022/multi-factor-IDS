import threading
from pathlib import Path
from network_monitor.packet_analyzer import NetworkMonitor  # Replace with your actual module import

# Dummy alert callback
def alert_callback(alert):
    print("ALERT:", alert)

# Shutdown event
shutdown_event = threading.Event()

# Config with empty capture filter
config = {
    "network": {
        "interfaces": ["\\Device\\NPF_{A9AC6786-50AA-42B0-9B9A-8A580A2E8299}"],  # Use the interface that carries your chat traffic
        "capture_filter": "",      # Empty means capture all packets
        "packet_timeout": 10,
        "max_packets": 20          # Small number for test
    }
}

# Initialize monitor
monitor = NetworkMonitor(config=config, alert_callback=alert_callback, shutdown_event=shutdown_event)

# Start capture in a separate thread so it doesn't block
capture_thread = threading.Thread(target=monitor.start)
capture_thread.start()

# Wait for capture to finish
capture_thread.join()

# Check recent events in database
events = monitor.get_recent_events(limit=20)
for e in events:
    print(e)
