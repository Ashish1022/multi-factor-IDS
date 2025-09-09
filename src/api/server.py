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

class APIServer:
    """REST API server for IDS management"""
    
    def __init__(self, config: Dict[str, Any], ids_components: Dict[str, Any]):
        self.config = config
        self.ids_components = ids_components
        
        from flask import Flask, jsonify, request
        from flask_cors import CORS
        
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.setup_routes()
        
    def setup_routes(self):
        """Setup API routes"""
        from flask import jsonify, request
        
        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            return jsonify({
                'status': 'running',
                'timestamp': datetime.now().isoformat(),
                'components': {
                    name: 'active' for name in self.ids_components.keys()
                }
            })
        
        @self.app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity')
            status = request.args.get('status')
            
            alert_manager = self.ids_components.get('alert_manager')
            if alert_manager:
                alerts = alert_manager.get_alerts(limit, severity, status)
                return jsonify({'alerts': alerts})
            else:
                return jsonify({'error': 'Alert manager not available'}), 500
        
        @self.app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
        def acknowledge_alert(alert_id):
            user = request.json.get('user', 'api')
            
            alert_manager = self.ids_components.get('alert_manager')
            if alert_manager:
                success = alert_manager.acknowledge_alert(alert_id, user)
                return jsonify({'success': success})
            else:
                return jsonify({'error': 'Alert manager not available'}), 500
        
        @self.app.route('/api/statistics', methods=['GET'])
        def get_statistics():
            stats = {}
            
            # Network statistics
            network_monitor = self.ids_components.get('network_monitor')
            if network_monitor:
                stats['network'] = network_monitor.get_statistics()
            
            # Alert statistics
            alert_manager = self.ids_components.get('alert_manager')
            if alert_manager:
                stats['alerts'] = alert_manager.get_alert_statistics()
            
            return jsonify(stats)
    
    def start(self):
        """Start API server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 5001)
        debug = self.config.get('debug', False)
        
        self.app.run(host=host, port=port, debug=debug, threaded=True)