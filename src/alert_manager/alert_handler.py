#!/usr/bin/env python3
"""
Alert Manager - Intelligent Alert Handling and Notification
src/alert_manager/alert_handler.py
"""

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

class AlertManager:
    """Manage, prioritize, and distribute security alerts"""
    
    def __init__(self, config: Dict[str, Any], shutdown_event: threading.Event):
        self.config = config
        self.shutdown_event = shutdown_event
        
        # Configuration
        self.severity_levels = config.get('severity_levels', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        self.notification_methods = config.get('notification_methods', ['email'])
        self.email_config = config.get('email', {})
        self.webhook_config = config.get('webhook', {})
        
        # Alert storage and processing
        self.alert_queue = deque()
        self.alert_history = deque(maxlen=10000)
        self.alert_stats = defaultdict(int)
        self.suppressed_alerts = defaultdict(int)
        
        # Rate limiting and deduplication
        self.alert_cache = {}
        self.rate_limits = {
            'CRITICAL': {'max_alerts': 10, 'time_window': 300},  # 10 per 5 minutes
            'HIGH': {'max_alerts': 20, 'time_window': 600},      # 20 per 10 minutes
            'MEDIUM': {'max_alerts': 50, 'time_window': 1800},   # 50 per 30 minutes
            'LOW': {'max_alerts': 100, 'time_window':