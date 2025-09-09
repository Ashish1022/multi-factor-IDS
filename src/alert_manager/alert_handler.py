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
            'LOW': {'max_alerts': 100, 'time_window': 3600}      # 100 per hour
        }
        
        # Database
        self.db_path = Path("data/alerts.db")
        self.init_database()
        
        self.logger = self._setup_logger()
        
        # Threading
        self.processing_thread = None
        
    def _setup_logger(self):
        import logging
        return logging.getLogger('AlertManager')
    
    def init_database(self):
        """Initialize alerts database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_id TEXT UNIQUE NOT NULL,
                component TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT,
                description TEXT,
                source_ip TEXT,
                target_ip TEXT,
                user_name TEXT,
                file_path TEXT,
                process_name TEXT,
                raw_data TEXT,
                status TEXT DEFAULT 'NEW',
                acknowledged BOOLEAN DEFAULT FALSE,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                resolved BOOLEAN DEFAULT FALSE,
                resolved_by TEXT,
                resolved_at TEXT,
                suppressed BOOLEAN DEFAULT FALSE,
                notification_sent BOOLEAN DEFAULT FALSE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                UNIQUE(date, severity, alert_type)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
        
        conn.commit()
        conn.close()
    
    def handle_alert(self, alert_data: Dict[str, Any]):
        """Handle incoming alert"""
        try:
            # Normalize alert
            normalized_alert = self._normalize_alert(alert_data)
            
            # Check for duplicates and rate limiting
            if self._should_suppress_alert(normalized_alert):
                self.suppressed_alerts[normalized_alert['alert_type']] += 1
                self.logger.debug(f"Alert suppressed: {normalized_alert['alert_type']}")
                return
            
            # Add to queue for processing
            self.alert_queue.append(normalized_alert)
            self.alert_history.append(normalized_alert)
            
            # Update statistics
            self.alert_stats[normalized_alert['severity']] += 1
            self.alert_stats[f"type_{normalized_alert['alert_type']}"] += 1
            
            self.logger.info(f"Alert queued: {normalized_alert['alert_type']} - {normalized_alert['severity']}")
            
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}")
    
    def _normalize_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize alert data format"""
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        
        normalized = {
            'timestamp': timestamp,
            'alert_id': alert_data.get('alert_id', f"alert_{int(time.time())}_{hash(str(alert_data)) % 10000}"),
            'component': alert_data.get('component', 'Unknown'),
            'alert_type': alert_data.get('alert_type', alert_data.get('threat_type', 'UNKNOWN')),
            'severity': alert_data.get('severity', 'MEDIUM'),
            'title': alert_data.get('title', alert_data.get('alert_type', 'Security Alert')),
            'description': alert_data.get('description', 'No description available'),
            'source_ip': alert_data.get('source_ip'),
            'target_ip': alert_data.get('target_ip', alert_data.get('dest_ip')),
            'user_name': alert_data.get('user', alert_data.get('username')),
            'file_path': alert_data.get('file_path'),
            'process_name': alert_data.get('process_name'),
            'raw_data': json.dumps(alert_data),
            'status': 'NEW',
            'acknowledged': False,
            'resolved': False,
            'suppressed': False,
            'notification_sent': False
        }
        
        return normalized
    
    def _should_suppress_alert(self, alert: Dict[str, Any]) -> bool:
        """Check if alert should be suppressed due to rate limiting or deduplication"""
        alert_key = f"{alert['component']}:{alert['alert_type']}:{alert.get('source_ip', '')}"
        current_time = time.time()
        
        # Check for exact duplicates in recent history
        for recent_alert in list(self.alert_history)[-50:]:  # Check last 50 alerts
            if (recent_alert['alert_type'] == alert['alert_type'] and
                recent_alert.get('source_ip') == alert.get('source_ip') and
                recent_alert['component'] == alert['component']):
                
                # Check if it's within deduplication window (5 minutes)
                try:
                    recent_time = datetime.fromisoformat(recent_alert['timestamp'].replace('Z', '+00:00'))
                    current_time_dt = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                    time_diff = (current_time_dt - recent_time).total_seconds()
                    
                    if time_diff < 300:  # 5 minutes
                        return True
                except (ValueError, TypeError):
                    pass
        
        # Check rate limiting
        severity = alert['severity']
        if severity in self.rate_limits:
            rate_config = self.rate_limits[severity]
            
            if alert_key not in self.alert_cache:
                self.alert_cache[alert_key] = deque()
            
            # Clean old entries
            cutoff_time = current_time - rate_config['time_window']
            while (self.alert_cache[alert_key] and 
                   self.alert_cache[alert_key][0] < cutoff_time):
                self.alert_cache[alert_key].popleft()
            
            # Check if rate limit exceeded
            if len(self.alert_cache[alert_key]) >= rate_config['max_alerts']:
                return True
            
            # Add current alert to cache
            self.alert_cache[alert_key].append(current_time)
        
        return False
    
    def _process_alerts(self):
        """Process alerts in queue"""
        while not self.shutdown_event.is_set():
            try:
                if self.alert_queue:
                    alert = self.alert_queue.popleft()
                    self._handle_single_alert(alert)
                else:
                    time.sleep(1)  # Wait for alerts
                    
            except Exception as e:
                self.logger.error(f"Error processing alerts: {e}")
                time.sleep(5)
    
    def _handle_single_alert(self, alert: Dict[str, Any]):
        """Handle a single alert"""
        try:
            # Store in database
            self._store_alert(alert)
            
            # Send notifications based on severity
            if alert['severity'] in ['HIGH', 'CRITICAL']:
                self._send_notifications(alert)
                alert['notification_sent'] = True
            
            # Auto-acknowledge low priority alerts from known sources
            if self._should_auto_acknowledge(alert):
                self._acknowledge_alert(alert['alert_id'], 'system')
            
            self.logger.debug(f"Processed alert: {alert['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Error handling single alert: {e}")
    
    def _store_alert(self, alert: Dict[str, Any]):
        """Store alert in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO alerts 
                (timestamp, alert_id, component, alert_type, severity, title, 
                 description, source_ip, target_ip, user_name, file_path, 
                 process_name, raw_data, status, notification_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['alert_id'],
                alert['component'],
                alert['alert_type'],
                alert['severity'],
                alert['title'],
                alert['description'],
                alert['source_ip'],
                alert['target_ip'],
                alert['user_name'],
                alert['file_path'],
                alert['process_name'],
                alert['raw_data'],
                alert['status'],
                alert['notification_sent']
            ))
            
            # Update daily statistics
            alert_date = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00')).date()
            cursor.execute('''
                INSERT OR IGNORE INTO alert_stats (date, severity, alert_type, count)
                VALUES (?, ?, ?, 0)
            ''', (str(alert_date), alert['severity'], alert['alert_type']))
            
            cursor.execute('''
                UPDATE alert_stats 
                SET count = count + 1
                WHERE date = ? AND severity = ? AND alert_type = ?
            ''', (str(alert_date), alert['severity'], alert['alert_type']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing alert: {e}")
    
    def _should_auto_acknowledge(self, alert: Dict[str, Any]) -> bool:
        """Check if alert should be auto-acknowledged"""
        # Auto-acknowledge low severity alerts from internal sources
        if alert['severity'] == 'LOW':
            source_ip = alert.get('source_ip')
            if source_ip and self._is_internal_ip(source_ip):
                return True
        
        # Auto-acknowledge known false positives
        false_positive_patterns = [
            'SYSTEM_PROCESS',
            'SCHEDULED_TASK',
            'BACKUP_ACTIVITY'
        ]
        
        for pattern in false_positive_patterns:
            if pattern in alert.get('alert_type', ''):
                return True
        
        return False
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is internal"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            
            # Check private ranges
            private_ranges = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('127.0.0.0/8')
            ]
            
            return any(ip in network for network in private_ranges)
            
        except ValueError:
            return False
    
    def _send_notifications(self, alert: Dict[str, Any]):
        """Send alert notifications"""
        try:
            for method in self.notification_methods:
                if method == 'email':
                    self._send_email_notification(alert)
                elif method == 'webhook':
                    self._send_webhook_notification(alert)
                elif method == 'syslog':
                    self._send_syslog_notification(alert)
                    
        except Exception as e:
            self.logger.error(f"Error sending notifications: {e}")
    
    def _send_email_notification(self, alert: Dict[str, Any]):
        """Send email notification"""
        try:
            if not self.email_config:
                return
            
            # Create email
            msg = MIMEMultipart()
            msg['From'] = self.email_config.get('username', 'zero.business.hub@gmail.com')
            msg['To'] = self.email_config.get('recipients', 'ashishjadhav9900@gmail.com')
            msg['Subject'] = f"[IDS Alert - {alert['severity']}] {alert['title']}"
            
            # Email body
            body = f"""
Security Alert Generated

Alert Details:
- Alert ID: {alert['alert_id']}
- Timestamp: {alert['timestamp']}
- Component: {alert['component']}
- Type: {alert['alert_type']}
- Severity: {alert['severity']}
- Description: {alert['description']}

Additional Information:
- Source IP: {alert.get('source_ip', 'N/A')}
- Target IP: {alert.get('target_ip', 'N/A')}
- User: {alert.get('user_name', 'N/A')}
- File Path: {alert.get('file_path', 'N/A')}
- Process: {alert.get('process_name', 'N/A')}

Please investigate this alert promptly.

This is an automated message from the Multi-Factor IDS.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            smtp_server = smtplib.SMTP(
                self.email_config.get('smtp_server', 'smtp.gmail.com'),
                self.email_config.get('smtp_port', 465)
            )
            smtp_server.starttls()
            smtp_server.login(
                self.email_config.get('username'),
                self.email_config.get('password')
            )
            smtp_server.send_message(msg)
            smtp_server.quit()
            
            self.logger.info(f"Email notification sent for alert: {alert['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {e}")
    
    def _send_webhook_notification(self, alert: Dict[str, Any]):
        """Send webhook notification"""
        try:
            if not self.webhook_config.get('url'):
                return
            
            payload = {
                'alert_id': alert['alert_id'],
                'timestamp': alert['timestamp'],
                'component': alert['component'],
                'alert_type': alert['alert_type'],
                'severity': alert['severity'],
                'title': alert['title'],
                'description': alert['description'],
                'source_ip': alert.get('source_ip'),
                'target_ip': alert.get('target_ip'),
                'user_name': alert.get('user_name')
            }
            
            response = requests.post(
                self.webhook_config['url'],
                json=payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook notification sent for alert: {alert['alert_id']}")
            else:
                self.logger.warning(f"Webhook notification failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending webhook notification: {e}")
    
    def _send_syslog_notification(self, alert: Dict[str, Any]):
        """Send syslog notification"""
        try:
            import syslog
            
            severity_map = {
                'LOW': syslog.LOG_INFO,
                'MEDIUM': syslog.LOG_WARNING,
                'HIGH': syslog.LOG_ERR,
                'CRITICAL': syslog.LOG_CRIT
            }
            
            syslog_severity = severity_map.get(alert['severity'], syslog.LOG_WARNING)
            
            message = f"IDS Alert [{alert['alert_id']}] {alert['alert_type']}: {alert['description']}"
            syslog.syslog(syslog_severity, message)
            
            self.logger.debug(f"Syslog notification sent for alert: {alert['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Error sending syslog notification: {e}")
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert"""
        return self._acknowledge_alert(alert_id, user)
    
    def _acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Internal method to acknowledge alert"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE alerts 
                SET acknowledged = TRUE, acknowledged_by = ?, acknowledged_at = ?, status = 'ACKNOWLEDGED'
                WHERE alert_id = ?
            ''', (user, datetime.now().isoformat(), alert_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self.logger.info(f"Alert acknowledged: {alert_id} by {user}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error acknowledging alert: {e}")
            return False
    
    def resolve_alert(self, alert_id: str, user: str) -> bool:
        """Resolve an alert"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE alerts 
                SET resolved = TRUE, resolved_by = ?, resolved_at = ?, status = 'RESOLVED'
                WHERE alert_id = ?
            ''', (user, datetime.now().isoformat(), alert_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self.logger.info(f"Alert resolved: {alert_id} by {user}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error resolving alert: {e}")
            return False
    
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, 
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts from database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts"
            params = []
            conditions = []
            
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            if status:
                conditions.append("status = ?")
                params.append(status)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [description[0] for description in cursor.description]
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Get daily stats for last 7 days
            seven_days_ago = (datetime.now() - timedelta(days=7)).date()
            cursor.execute('''
                SELECT date, severity, SUM(count) as total
                FROM alert_stats 
                WHERE date >= ?
                GROUP BY date, severity
                ORDER BY date DESC
            ''', (str(seven_days_ago),))
            
            daily_stats = cursor.fetchall()
            
            # Get total counts by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE date(timestamp) >= ?
                GROUP BY severity
            ''', (str(seven_days_ago),))
            
            severity_counts = dict(cursor.fetchall())
            
            # Get alert types
            cursor.execute('''
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                WHERE date(timestamp) >= ?
                GROUP BY alert_type
                ORDER BY count DESC
                LIMIT 10
            ''', (str(seven_days_ago),))
            
            top_alert_types = cursor.fetchall()
            
            conn.close()
            
            return {
                'daily_stats': daily_stats,
                'severity_counts': severity_counts,
                'top_alert_types': top_alert_types,
                'total_alerts': sum(severity_counts.values()),
                'suppressed_alerts': dict(self.suppressed_alerts)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting alert statistics: {e}")
            return {}
    
    def start(self):
        """Start alert manager"""
        self.logger.info("Starting alert manager...")
        
        # Start processing thread
        self.processing_thread = threading.Thread(
            target=self._process_alerts,
            daemon=True
        )
        self.processing_thread.start()
        
        # Main monitoring loop
        while not self.shutdown_event.is_set():
            try:
                # Cleanup old alerts
                self._cleanup_old_alerts()
                
                # Generate summary reports
                if datetime.now().hour == 8 and datetime.now().minute == 0:  # 8 AM daily
                    self._generate_daily_summary()
                
                # Wait before next cycle
                self.shutdown_event.wait(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Error in alert manager main loop: {e}")
                time.sleep(3600)
    
    def _cleanup_old_alerts(self):
        """Cleanup old alerts from database"""
        try:
            cutoff_date = datetime.now() - timedelta(days=90)  # Keep 90 days
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date.isoformat(),))
            deleted_count = cursor.rowcount
            
            # Cleanup old stats
            stats_cutoff = (datetime.now() - timedelta(days=365)).date()  # Keep 1 year of stats
            cursor.execute('DELETE FROM alert_stats WHERE date < ?', (str(stats_cutoff),))
            
            conn.commit()
            conn.close()
            
            if deleted_count > 0:
                self.logger.info(f"Cleaned up {deleted_count} old alerts")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old alerts: {e}")
    
    def _generate_daily_summary(self):
        """Generate daily alert summary"""
        try:
            yesterday = (datetime.now() - timedelta(days=1)).date()
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE date(timestamp) = ?
                GROUP BY severity
            ''', (str(yesterday),))
            
            daily_counts = dict(cursor.fetchall())
            total_alerts = sum(daily_counts.values())
            
            if total_alerts > 0:
                summary = {
                    'date': str(yesterday),
                    'total_alerts': total_alerts,
                    'severity_breakdown': daily_counts,
                    'generated_at': datetime.now().isoformat()
                }
                
                self.logger.info(f"Daily summary for {yesterday}: {total_alerts} alerts")
                
                # Could send summary via email or webhook
                
        except Exception as e:
            self.logger.error(f"Error generating daily summary: {e}")