import smtplib
import json
import threading
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

class ConfigLoader:
    """Configuration loader and manager"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_path.exists():
                import yaml
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            else:
                print(f"Warning: Config file not found: {self.config_path}")
                self.config = self._get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}")
            self.config = self._get_default_config()
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'global': {
                'log_level': 'INFO',
                'data_retention_days': 90,
                'timezone': 'UTC'
            },
            'network': {
                'interfaces': ['eth0'],
                'capture_filter': 'tcp or udp or icmp',
                'promiscuous_mode': True
            },
            'host': {
                'monitor_processes': True,
                'monitor_files': True,
                'scan_interval': 30
            },
            'baseline': {
                'learning_period_days': 7,
                'update_interval_hours': 24,
                'anomaly_threshold': 0.95
            },
            'alerts': {
                'severity_levels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                'notification_methods': ['email']
            }
        }
