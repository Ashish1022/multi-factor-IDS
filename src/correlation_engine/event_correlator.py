import os
import time
import json
import pickle
import threading
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, List, Optional
from collections import defaultdict, deque
from pathlib import Path
import sqlite3

# =============================================================================
# Correlation Engine
# =============================================================================

class CorrelationEngine:
    """Multi-source event correlation and analysis"""
    
    def __init__(self, config: Dict[str, Any], alert_callback: Callable, shutdown_event: threading.Event):
        self.config = config
        self.alert_callback = alert_callback
        self.shutdown_event = shutdown_event
        
        # Configuration
        self.time_window_minutes = config.get('time_window_minutes', 5)
        self.max_events_per_window = config.get('max_events_per_window', 10000)
        self.correlation_threshold = config.get('correlation_threshold', 0.8)
        self.rules_file = config.get('rules_file', 'config/correlation_rules.yaml')
        
        # Event storage
        self.event_buffer = deque(maxlen=self.max_events_per_window)
        self.correlation_rules = []
        self.db_path = Path("data/correlation_events.db")
        
        # Pattern tracking
        self.attack_patterns = {}
        self.ip_reputation = defaultdict(lambda: {'score': 0, 'events': []})
        
        self.logger = self._setup_logger()
        self.init_database()
        self.load_correlation_rules()
    
    def _setup_logger(self):
        import logging
        return logging.getLogger('CorrelationEngine')
    
    def init_database(self):
        """Initialize correlation database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id TEXT,
                component TEXT,
                event_type TEXT,
                severity TEXT,
                source_ip TEXT,
                target_ip TEXT,
                correlation_score REAL,
                pattern_matched TEXT,
                raw_event TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT UNIQUE NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                attack_type TEXT,
                source_ips TEXT,
                target_ips TEXT,
                event_count INTEGER,
                severity TEXT,
                description TEXT,
                status TEXT DEFAULT 'ACTIVE'
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_corr_timestamp ON correlation_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_corr_source_ip ON correlation_events(source_ip)')
        
        conn.commit()
        conn.close()
    
    def load_correlation_rules(self):
        """Load correlation rules from configuration"""
        # Default correlation rules
        self.correlation_rules = [
            {
                'name': 'Port Scan to Exploitation',
                'description': 'Port scan followed by exploitation attempt',
                'events': [
                    {'type': 'PORT_SCAN', 'timeframe': 300},
                    {'type': 'SUSPICIOUS_CONNECTION', 'timeframe': 600}
                ],
                'correlation_fields': ['source_ip'],
                'severity': 'HIGH',
                'confidence': 0.8
            },
            {
                'name': 'Brute Force Attack',
                'description': 'Multiple failed login attempts',
                'events': [
                    {'type': 'FAILED_LOGIN', 'count': 5, 'timeframe': 300}
                ],
                'correlation_fields': ['source_ip', 'target_ip'],
                'severity': 'MEDIUM',
                'confidence': 0.9
            },
            {
                'name': 'Data Exfiltration',
                'description': 'Suspicious file access followed by network activity',
                'events': [
                    {'type': 'FILE_ACCESS', 'timeframe': 300},
                    {'type': 'LARGE_UPLOAD', 'timeframe': 600}
                ],
                'correlation_fields': ['user', 'source_ip'],
                'severity': 'CRITICAL',
                'confidence': 0.85
            },
            {
                'name': 'Malware Installation',
                'description': 'File creation in system directories followed by process execution',
                'events': [
                    {'type': 'FILE_CREATED', 'timeframe': 60},
                    {'type': 'NEW_PROCESS', 'timeframe': 120}
                ],
                'correlation_fields': ['file_path', 'process_name'],
                'severity': 'HIGH',
                'confidence': 0.75
            },
            {
                'name': 'Privilege Escalation',
                'description': 'Process anomaly followed by file system changes',
                'events': [
                    {'type': 'SUSPICIOUS_PROCESS', 'timeframe': 300},
                    {'type': 'FILE_MODIFIED', 'timeframe': 600}
                ],
                'correlation_fields': ['user', 'source_ip'],
                'severity': 'CRITICAL',
                'confidence': 0.8
            }
        ]
        
        self.logger.info(f"Loaded {len(self.correlation_rules)} correlation rules")
    
    def process_event(self, event: Dict[str, Any]):
        """Process incoming event for correlation"""
        try:
            # Normalize event
            normalized_event = self._normalize_event(event)
            
            # Add to buffer
            self.event_buffer.append(normalized_event)
            
            # Store in database
            self._store_correlation_event(normalized_event)
            
            # Update IP reputation
            self._update_ip_reputation(normalized_event)
            
            # Run correlation analysis
            correlations = self._correlate_events(normalized_event)
            
            # Process correlations
            for correlation in correlations:
                self._handle_correlation(correlation)
                
        except Exception as e:
            self.logger.error(f"Error processing event for correlation: {e}")
    
    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize event format for correlation"""
        normalized = {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'event_id': event.get('id', f"evt_{int(time.time())}_{hash(str(event)) % 10000}"),
            'component': event.get('component', 'Unknown'),
            'event_type': event.get('alert_type', event.get('event_type', 'UNKNOWN')),
            'severity': event.get('severity', 'MEDIUM'),
            'source_ip': event.get('source_ip'),
            'target_ip': event.get('dest_ip', event.get('target_ip')),
            'user': event.get('user'),
            'file_path': event.get('file_path'),
            'process_name': event.get('process_name'),
            'process_id': event.get('process_id'),
            'description': event.get('description', ''),
            'raw_event': json.dumps(event)
        }
        
        return normalized
    
    def _store_correlation_event(self, event: Dict[str, Any]):
        """Store correlation event in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO correlation_events 
                (timestamp, event_id, component, event_type, severity, 
                 source_ip, target_ip, raw_event)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['timestamp'],
                event['event_id'],
                event['component'],
                event['event_type'],
                event['severity'],
                event['source_ip'],
                event['target_ip'],
                event['raw_event']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing correlation event: {e}")
    
    def _update_ip_reputation(self, event: Dict[str, Any]):
        """Update IP reputation based on event"""
        source_ip = event.get('source_ip')
        if not source_ip:
            return
        
        # Calculate reputation score based on event severity
        severity_scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 5, 'CRITICAL': 10}
        score = severity_scores.get(event.get('severity', 'MEDIUM'), 3)
        
        # Update reputation
        self.ip_reputation[source_ip]['score'] += score
        self.ip_reputation[source_ip]['events'].append({
            'timestamp': event['timestamp'],
            'event_type': event['event_type'],
            'severity': event['severity']
        })
        
        # Limit event history
        if len(self.ip_reputation[source_ip]['events']) > 100:
            self.ip_reputation[source_ip]['events'] = self.ip_reputation[source_ip]['events'][-50:]
        
        # Generate reputation alert if threshold exceeded
        if self.ip_reputation[source_ip]['score'] > 50:
            self._generate_reputation_alert(source_ip, self.ip_reputation[source_ip])
    
    def _correlate_events(self, current_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate current event with recent events"""
        correlations = []
        
        try:
            current_time = datetime.fromisoformat(current_event['timestamp'].replace('Z', '+00:00'))
            
            for rule in self.correlation_rules:
                correlation = self._apply_correlation_rule(current_event, rule, current_time)
                if correlation:
                    correlations.append(correlation)
            
        except Exception as e:
            self.logger.error(f"Error correlating events: {e}")
        
        return correlations
    
    def _apply_correlation_rule(self, current_event: Dict[str, Any], rule: Dict[str, Any], current_time: datetime) -> Optional[Dict[str, Any]]:
        """Apply specific correlation rule"""
        try:
            rule_events = rule['events']
            correlation_fields = rule['correlation_fields']
            
            # Find matching events in time window
            matching_events = []
            
            for rule_event in rule_events:
                event_type = rule_event['type']
                timeframe = rule_event.get('timeframe', 300)  # seconds
                required_count = rule_event.get('count', 1)
                
                # Search for matching events
                matches = []
                time_threshold = current_time - timedelta(seconds=timeframe)
                
                for event in reversed(self.event_buffer):
                    try:
                        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                        
                        if event_time < time_threshold:
                            break  # Events are ordered by time
                        
                        if event['event_type'] == event_type:
                            # Check if correlation fields match
                            if self._events_correlate(current_event, event, correlation_fields):
                                matches.append(event)
                                
                    except (ValueError, TypeError):
                        continue
                
                # Check if we have enough matches
                if len(matches) >= required_count:
                    matching_events.extend(matches[:required_count])
                else:
                    return None  # Rule not satisfied
            
            # If we reach here, rule is satisfied
            correlation = {
                'rule_name': rule['name'],
                'description': rule['description'],
                'severity': rule['severity'],
                'confidence': rule['confidence'],
                'trigger_event': current_event,
                'matching_events': matching_events,
                'correlation_fields': correlation_fields,
                'timestamp': current_time.isoformat()
            }
            
            return correlation
            
        except Exception as e:
            self.logger.error(f"Error applying correlation rule {rule.get('name', 'unknown')}: {e}")
            return None
    
    def _events_correlate(self, event1: Dict[str, Any], event2: Dict[str, Any], correlation_fields: List[str]) -> bool:
        """Check if two events correlate based on specified fields"""
        for field in correlation_fields:
            value1 = event1.get(field)
            value2 = event2.get(field)
            
            if value1 and value2 and value1 == value2:
                return True
        
        return False
    
    def _handle_correlation(self, correlation: Dict[str, Any]):
        """Handle detected correlation"""
        try:
            # Generate correlation alert
            alert = {
                'timestamp': correlation['timestamp'],
                'component': 'CorrelationEngine',
                'alert_type': 'CORRELATED_ATTACK',
                'severity': correlation['severity'],
                'rule_name': correlation['rule_name'],
                'description': f"Correlated attack detected: {correlation['description']}",
                'confidence': correlation['confidence'],
                'trigger_event': correlation['trigger_event'],
                'matching_events': correlation['matching_events'],
                'correlation_fields': correlation['correlation_fields'],
                'event_count': len(correlation['matching_events']) + 1
            }
            
            # Send alert
            self.alert_callback(alert)
            
            # Create attack campaign if significant
            if correlation['severity'] in ['HIGH', 'CRITICAL']:
                self._create_attack_campaign(correlation)
            
            self.logger.warning(f"Correlation detected: {correlation['rule_name']} "
                              f"(confidence: {correlation['confidence']:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error handling correlation: {e}")
    
    def _create_attack_campaign(self, correlation: Dict[str, Any]):
        """Create attack campaign record"""
        try:
            campaign_id = f"campaign_{int(time.time())}_{hash(correlation['rule_name']) % 10000}"
            
            # Extract source and target IPs
            source_ips = set()
            target_ips = set()
            
            for event in [correlation['trigger_event']] + correlation['matching_events']:
                if event.get('source_ip'):
                    source_ips.add(event['source_ip'])
                if event.get('target_ip'):
                    target_ips.add(event['target_ip'])
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_campaigns 
                (campaign_id, start_time, attack_type, source_ips, target_ips, 
                 event_count, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                campaign_id,
                correlation['timestamp'],
                correlation['rule_name'],
                json.dumps(list(source_ips)),
                json.dumps(list(target_ips)),
                len(correlation['matching_events']) + 1,
                correlation['severity'],
                correlation['description']
            ))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Created attack campaign: {campaign_id}")
            
        except Exception as e:
            self.logger.error(f"Error creating attack campaign: {e}")
    
    def _generate_reputation_alert(self, ip_address: str, reputation_data: Dict[str, Any]):
        """Generate IP reputation alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'CorrelationEngine',
            'alert_type': 'HIGH_RISK_IP',
            'severity': 'HIGH',
            'source_ip': ip_address,
            'reputation_score': reputation_data['score'],
            'event_count': len(reputation_data['events']),
            'description': f"High-risk IP detected: {ip_address} (score: {reputation_data['score']})",
            'recent_events': reputation_data['events'][-10:]  # Last 10 events
        }
        
        self.alert_callback(alert)
        self.logger.warning(f"High-risk IP alert: {ip_address} (score: {reputation_data['score']})")
    
    def process_baseline_data(self, baseline_data: Dict[str, Any]):
        """Process data from baseline engine"""
        # Convert baseline anomalies to events
        if baseline_data.get('data_type') and baseline_data.get('confidence', 0) > 0.7:
            event = {
                'timestamp': baseline_data['timestamp'],
                'component': 'BaselineEngine',
                'alert_type': 'BEHAVIORAL_ANOMALY',
                'severity': 'MEDIUM' if baseline_data['confidence'] < 0.9 else 'HIGH',
                'data_type': baseline_data['data_type'],
                'confidence': baseline_data['confidence'],
                'description': f"Behavioral anomaly detected in {baseline_data['data_type']} data",
                'features': baseline_data.get('features', {}),
                'raw_data': baseline_data.get('raw_data', {})
            }
            
            self.process_event(event)
    
    def start(self):
        """Start correlation engine"""
        self.logger.info("Starting correlation engine...")
        
        while not self.shutdown_event.is_set():
            try:
                # Cleanup old events
                self._cleanup_old_events()
                
                # Update attack campaigns
                self._update_attack_campaigns()
                
                # Wait before next cycle
                self.shutdown_event.wait(30)  # Run every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in correlation engine main loop: {e}")
                time.sleep(30)
    
    def _cleanup_old_events(self):
        """Cleanup old events from database"""
        try:
            cutoff_time = datetime.now() - timedelta(days=7)  # Keep 7 days
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM correlation_events 
                WHERE timestamp < ?
            ''', (cutoff_time.isoformat(),))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if deleted_count > 0:
                self.logger.debug(f"Cleaned up {deleted_count} old correlation events")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old events: {e}")
    
    def _update_attack_campaigns(self):
        """Update status of active attack campaigns"""
        try:
            # Close campaigns that haven't had activity in 24 hours
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE attack_campaigns 
                SET status = 'CLOSED', end_time = ?
                WHERE status = 'ACTIVE' AND start_time < ?
            ''', (datetime.now().isoformat(), cutoff_time.isoformat()))
            
            updated_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if updated_count > 0:
                self.logger.info(f"Closed {updated_count} inactive attack campaigns")
                
        except Exception as e:
            self.logger.error(f"Error updating attack campaigns: {e}")