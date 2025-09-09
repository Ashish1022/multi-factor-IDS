import time
import threading
from datetime import datetime
from typing import Dict, Any, Callable, Optional
from collections import defaultdict, deque
import json
import hashlib

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Warning: Scapy not installed. Network monitoring will be limited.")
    sniff = None

import psutil
import sqlite3
from pathlib import Path

class NetworkMonitor:
    """Network traffic monitoring and analysis"""
    
    def __init__(self, config: Dict[str, Any], alert_callback: Callable, shutdown_event: threading.Event):
        self.config = config
        self.alert_callback = alert_callback
        self.shutdown_event = shutdown_event
        
        # Configuration
        self.interfaces = config.get('interfaces', ['eth0'])
        self.capture_filter = config.get('capture_filter', 'tcp or udp or icmp')
        self.packet_timeout = config.get('packet_timeout', 10)
        self.max_packets = config.get('max_packets', 1000)
        
        # Statistics and tracking
        self.packet_count = 0
        self.traffic_stats = defaultdict(int)
        self.connection_tracker = defaultdict(dict)
        self.suspicious_ips = set()
        self.recent_packets = deque(maxlen=1000)
        
        # Database for storing network events
        self.db_path = Path("data/network_events.db")
        self.init_database()
        
        # Anomaly detection
        self.port_scan_detector = PortScanDetector()
        self.dos_detector = DosDetector()
        self.suspicious_payload_detector = SuspiciousPayloadDetector()
        
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup component logger"""
        import logging
        logger = logging.getLogger('NetworkMonitor')
        return logger
    
    def init_database(self):
        """Initialize SQLite database for network events"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                payload_hash TEXT,
                suspicious BOOLEAN DEFAULT FALSE,
                threat_type TEXT,
                severity TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON network_events(timestamp);
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_source_ip ON network_events(source_ip);
        ''')
        
        conn.commit()
        conn.close()
    
    def get_available_interfaces(self) -> list:
        """Get list of available network interfaces"""
        if sniff is None:
            # Fallback to psutil
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                if any(addr.family == 2 for addr in addrs):  # IPv4
                    interfaces.append(interface)
            return interfaces
        else:
            return get_if_list()
    
    def packet_handler(self, packet):
        """Handle captured network packets"""
        try:
            self.packet_count += 1
            timestamp = datetime.now()
            
            # Basic packet info
            packet_info = {
                'timestamp': timestamp.isoformat(),
                'size': len(packet),
                'protocol': None,
                'source_ip': None,
                'dest_ip': None,
                'source_port': None,
                'dest_port': None,
                'flags': None,
                'suspicious': False,
                'threat_type': None,
                'severity': 'LOW'
            }
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                packet_info.update({
                    'source_ip': ip_layer.src,
                    'dest_ip': ip_layer.dst,
                    'protocol': ip_layer.proto
                })
                
                # TCP analysis
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info.update({
                        'source_port': tcp_layer.sport,
                        'dest_port': tcp_layer.dport,
                        'flags': str(tcp_layer.flags),
                        'protocol': 'TCP'
                    })
                    
                    # Check for suspicious TCP activity
                    self._analyze_tcp_packet(packet_info, tcp_layer, packet)
                
                # UDP analysis
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info.update({
                        'source_port': udp_layer.sport,
                        'dest_port': udp_layer.dport,
                        'protocol': 'UDP'
                    })
                    
                    # Check for suspicious UDP activity
                    self._analyze_udp_packet(packet_info, udp_layer, packet)
                
                # ICMP analysis
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                    self._analyze_icmp_packet(packet_info, packet)
            
            # ARP analysis
            elif ARP in packet:
                arp_layer = packet[ARP]
                packet_info.update({
                    'source_ip': arp_layer.psrc,
                    'dest_ip': arp_layer.pdst,
                    'protocol': 'ARP'
                })
                self._analyze_arp_packet(packet_info, arp_layer)
            
            # Store packet info
            self.recent_packets.append(packet_info)
            self._store_packet_event(packet_info)
            
            # Update statistics
            self._update_statistics(packet_info)
            
            # Run anomaly detection
            self._run_anomaly_detection(packet_info, packet)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _analyze_tcp_packet(self, packet_info: dict, tcp_layer, packet):
        """Analyze TCP packet for suspicious activity"""
        src_ip = packet_info['source_ip']
        dst_ip = packet_info['dest_ip']
        dst_port = packet_info['dest_port']
        
        # Port scan detection
        if self.port_scan_detector.detect_port_scan(src_ip, dst_ip, dst_port):
            packet_info.update({
                'suspicious': True,
                'threat_type': 'PORT_SCAN',
                'severity': 'MEDIUM'
            })
            self._generate_alert('PORT_SCAN', packet_info)
        
        # SYN flood detection
        if tcp_layer.flags == 2:  # SYN flag
            if self.dos_detector.detect_syn_flood(src_ip, dst_ip):
                packet_info.update({
                    'suspicious': True,
                    'threat_type': 'SYN_FLOOD',
                    'severity': 'HIGH'
                })
                self._generate_alert('SYN_FLOOD', packet_info)
        
        # HTTP payload analysis
        if dst_port in [80, 8080] and packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])
            if self.suspicious_payload_detector.analyze_http_payload(payload):
                packet_info.update({
                    'suspicious': True,
                    'threat_type': 'SUSPICIOUS_HTTP',
                    'severity': 'MEDIUM'
                })
                self._generate_alert('SUSPICIOUS_HTTP', packet_info)
    
    def _analyze_udp_packet(self, packet_info: dict, udp_layer, packet):
        """Analyze UDP packet for suspicious activity"""
        src_ip = packet_info['source_ip']
        dst_port = packet_info['dest_port']
        
        # DNS analysis
        if dst_port == 53:
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw'])
                if self.suspicious_payload_detector.analyze_dns_payload(payload):
                    packet_info.update({
                        'suspicious': True,
                        'threat_type': 'SUSPICIOUS_DNS',
                        'severity': 'MEDIUM'
                    })
                    self._generate_alert('SUSPICIOUS_DNS', packet_info)
        
        # UDP flood detection
        if self.dos_detector.detect_udp_flood(src_ip):
            packet_info.update({
                'suspicious': True,
                'threat_type': 'UDP_FLOOD',
                'severity': 'HIGH'
            })
            self._generate_alert('UDP_FLOOD', packet_info)
    
    def _analyze_icmp_packet(self, packet_info: dict, packet):
        """Analyze ICMP packet for suspicious activity"""
        # ICMP flood detection
        src_ip = packet_info['source_ip']
        if self.dos_detector.detect_icmp_flood(src_ip):
            packet_info.update({
                'suspicious': True,
                'threat_type': 'ICMP_FLOOD',
                'severity': 'MEDIUM'
            })
            self._generate_alert('ICMP_FLOOD', packet_info)
    
    def _analyze_arp_packet(self, packet_info: dict, arp_layer):
        """Analyze ARP packet for suspicious activity"""
        # ARP spoofing detection (simplified)
        if arp_layer.op == 2:  # ARP reply
            # Check for duplicate IP announcements
            src_ip = arp_layer.psrc
            if src_ip in self.connection_tracker:
                if 'arp_mac' in self.connection_tracker[src_ip]:
                    if self.connection_tracker[src_ip]['arp_mac'] != arp_layer.hwsrc:
                        packet_info.update({
                            'suspicious': True,
                            'threat_type': 'ARP_SPOOFING',
                            'severity': 'HIGH'
                        })
                        self._generate_alert('ARP_SPOOFING', packet_info)
            
            self.connection_tracker[src_ip]['arp_mac'] = arp_layer.hwsrc
    
    def _run_anomaly_detection(self, packet_info: dict, packet):
        """Run additional anomaly detection algorithms"""
        # Add payload hash for forensics
        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])
            packet_info['payload_hash'] = hashlib.md5(payload).hexdigest()
    
    def _update_statistics(self, packet_info: dict):
        """Update traffic statistics"""
        protocol = packet_info.get('protocol', 'UNKNOWN')
        self.traffic_stats[f'protocol_{protocol}'] += 1
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['total_bytes'] += packet_info.get('size', 0)
        
        # Track unique IPs
        if packet_info.get('source_ip'):
            recent_src_ips = set([p.get('source_ip') for p in self.recent_packets if p.get('source_ip')])
            self.traffic_stats['unique_source_ips'] = len(recent_src_ips)
    
    def _store_packet_event(self, packet_info: dict):
        """Store packet event in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_events 
                (timestamp, source_ip, dest_ip, source_port, dest_port, 
                 protocol, packet_size, flags, payload_hash, suspicious, 
                 threat_type, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info['timestamp'],
                packet_info.get('source_ip'),
                packet_info.get('dest_ip'),
                packet_info.get('source_port'),
                packet_info.get('dest_port'),
                packet_info.get('protocol'),
                packet_info.get('size'),
                packet_info.get('flags'),
                packet_info.get('payload_hash'),
                packet_info.get('suspicious', False),
                packet_info.get('threat_type'),
                packet_info.get('severity')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing packet event: {e}")
    
    def _generate_alert(self, threat_type: str, packet_info: dict):
        """Generate security alert"""
        alert = {
            'timestamp': packet_info['timestamp'],
            'component': 'NetworkMonitor',
            'threat_type': threat_type,
            'severity': packet_info.get('severity', 'MEDIUM'),
            'source_ip': packet_info.get('source_ip'),
            'dest_ip': packet_info.get('dest_ip'),
            'source_port': packet_info.get('source_port'),
            'dest_port': packet_info.get('dest_port'),
            'protocol': packet_info.get('protocol'),
            'description': self._get_threat_description(threat_type),
            'raw_data': packet_info
        }
        
        self.alert_callback(alert)
        self.logger.warning(f"Security alert generated: {threat_type} from {packet_info.get('source_ip')}")
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get human-readable threat description"""
        descriptions = {
            'PORT_SCAN': 'Port scanning activity detected',
            'SYN_FLOOD': 'SYN flood attack detected',
            'UDP_FLOOD': 'UDP flood attack detected',
            'ICMP_FLOOD': 'ICMP flood attack detected',
            'ARP_SPOOFING': 'ARP spoofing attack detected',
            'SUSPICIOUS_HTTP': 'Suspicious HTTP payload detected',
            'SUSPICIOUS_DNS': 'Suspicious DNS query detected'
        }
        return descriptions.get(threat_type, f'Unknown threat: {threat_type}')
    
    def get_statistics(self) -> dict:
        """Get current network statistics"""
        return dict(self.traffic_stats)
    
    def get_recent_events(self, limit: int = 100) -> list:
        """Get recent network events"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM network_events 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [description[0] for description in cursor.description]
            events = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return events
            
        except Exception as e:
            self.logger.error(f"Error retrieving events: {e}")
            return []
    
    def start(self):
        """Start network monitoring"""
        self.logger.info("Starting network monitor...")
        
        # Validate interfaces
        available_interfaces = self.get_available_interfaces()
        valid_interfaces = [iface for iface in self.interfaces if iface in available_interfaces]
        
        if not valid_interfaces:
            self.logger.error(f"No valid interfaces found. Available: {available_interfaces}")
            return
        
        self.logger.info(f"Monitoring interfaces: {valid_interfaces}")
        
        try:
            if sniff is not None:
                # Start packet capture
                sniff(
                    iface=valid_interfaces,
                    prn=self.packet_handler,
                    filter=self.capture_filter,
                    timeout=self.packet_timeout,
                    count=self.max_packets,
                    stop_filter=lambda p: self.shutdown_event.is_set()
                )
            else:
                self.logger.warning("Scapy not available, using alternative monitoring")
                self._alternative_monitoring()
                
        except PermissionError:
            self.logger.error("Permission denied. Run as root or with CAP_NET_RAW capability")
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
    
    def _alternative_monitoring(self):
        """Alternative monitoring without scapy"""
        self.logger.info("Using psutil-based network monitoring")
        
        while not self.shutdown_event.is_set():
            try:
                # Monitor network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        event = {
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': conn.laddr.ip if conn.laddr else None,
                            'source_port': conn.laddr.port if conn.laddr else None,
                            'dest_ip': conn.raddr.ip if conn.raddr else None,
                            'dest_port': conn.raddr.port if conn.raddr else None,
                            'protocol': 'TCP' if conn.type == 1 else 'UDP',
                            'pid': conn.pid,
                            'status': conn.status
                        }
                        
                        # Simple anomaly detection
                        self._simple_anomaly_detection(event)
                
                # Monitor network I/O stats
                net_io = psutil.net_io_counters()
                self.traffic_stats.update({
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                })
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Alternative monitoring error: {e}")
                time.sleep(10)
    
    def _simple_anomaly_detection(self, event: dict):
        """Simple anomaly detection for alternative monitoring"""
        # Check for suspicious ports
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 12345]
        
        if event.get('dest_port') in suspicious_ports:
            event.update({
                'suspicious': True,
                'threat_type': 'SUSPICIOUS_PORT',
                'severity': 'MEDIUM'
            })
            self._generate_alert('SUSPICIOUS_PORT', event)

# =============================================================================
# Anomaly Detection Classes
# =============================================================================

class PortScanDetector:
    """Detect port scanning activities"""
    
    def __init__(self):
        self.scan_threshold = 10  # ports per minute
        self.time_window = 60  # seconds
        self.scan_tracking = defaultdict(lambda: defaultdict(set))
        self.last_cleanup = time.time()
    
    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        """Detect if source IP is port scanning destination IP"""
        current_time = time.time()
        
        # Cleanup old entries
        if current_time - self.last_cleanup > self.time_window:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Track port access
        self.scan_tracking[src_ip][dst_ip].add(dst_port)
        
        # Check if threshold exceeded
        unique_ports = len(self.scan_tracking[src_ip][dst_ip])
        return unique_ports > self.scan_threshold
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove old tracking entries"""
        # Simple cleanup - in production, you'd want timestamp-based cleanup
        if len(self.scan_tracking) > 1000:
            # Keep only recent entries
            self.scan_tracking.clear()

class DosDetector:
    """Detect Denial of Service attacks"""
    
    def __init__(self):
        self.syn_threshold = 100  # SYN packets per minute
        self.udp_threshold = 200  # UDP packets per minute
        self.icmp_threshold = 50  # ICMP packets per minute
        self.time_window = 60
        
        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.last_reset = time.time()
    
    def detect_syn_flood(self, src_ip: str, dst_ip: str) -> bool:
        """Detect SYN flood attack"""
        self._check_reset_counters()
        
        key = f"{src_ip}->{dst_ip}"
        self.syn_counts[key] += 1
        
        return self.syn_counts[key] > self.syn_threshold
    
    def detect_udp_flood(self, src_ip: str) -> bool:
        """Detect UDP flood attack"""
        self._check_reset_counters()
        
        self.udp_counts[src_ip] += 1
        return self.udp_counts[src_ip] > self.udp_threshold
    
    def detect_icmp_flood(self, src_ip: str) -> bool:
        """Detect ICMP flood attack"""
        self._check_reset_counters()
        
        self.icmp_counts[src_ip] += 1
        return self.icmp_counts[src_ip] > self.icmp_threshold
    
    def _check_reset_counters(self):
        """Reset counters after time window"""
        current_time = time.time()
        if current_time - self.last_reset > self.time_window:
            self.syn_counts.clear()
            self.udp_counts.clear()
            self.icmp_counts.clear()
            self.last_reset = current_time

class SuspiciousPayloadDetector:
    """Detect suspicious payloads in network traffic"""
    
    def __init__(self):
        # Common attack signatures
        self.http_signatures = [
            b'<script',
            b'javascript:',
            b'eval(',
            b'document.cookie',
            b'../../../',
            b'SELECT * FROM',
            b'UNION SELECT',
            b'DROP TABLE',
            b'<iframe',
            b'onload=',
            b'onerror='
        ]
        
        self.dns_suspicious_domains = [
            '.tk',
            '.ml', 
            '.ga',
            '.cf',
            'dga-domain',
            'malware-c2'
        ]
    
    def analyze_http_payload(self, payload: bytes) -> bool:
        """Analyze HTTP payload for suspicious content"""
        try:
            payload_lower = payload.lower()
            
            for signature in self.http_signatures:
                if signature in payload_lower:
                    return True
            
            # Check for SQL injection patterns
            if self._detect_sql_injection(payload_lower):
                return True
            
            # Check for XSS patterns
            if self._detect_xss(payload_lower):
                return True
                
        except Exception:
            pass
        
        return False
    
    def analyze_dns_payload(self, payload: bytes) -> bool:
        """Analyze DNS payload for suspicious queries"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            # Check for suspicious TLDs
            for domain in self.dns_suspicious_domains:
                if domain in payload_str:
                    return True
            
            # Check for domain generation algorithm patterns
            if self._detect_dga_domain(payload_str):
                return True
                
        except Exception:
            pass
        
        return False
    
    def _detect_sql_injection(self, payload: bytes) -> bool:
        """Detect SQL injection attempts"""
        sql_patterns = [
            b"' or 1=1",
            b"' or '1'='1",
            b"admin'--",
            b"'; drop table",
            b"' union select"
        ]
        
        for pattern in sql_patterns:
            if pattern in payload:
                return True
        return False
    
    def _detect_xss(self, payload: bytes) -> bool:
        """Detect XSS attempts"""
        xss_patterns = [
            b"<script>alert(",
            b"javascript:alert(",
            b"<img src=x onerror=",
            b"<svg onload="
        ]
        
        for pattern in xss_patterns:
            if pattern in payload:
                return True
        return False
    
    def _detect_dga_domain(self, domain: str) -> bool:
        """Detect domain generation algorithm domains"""
        # Simple heuristic: high entropy random-looking domains
        if len(domain) > 10:
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            
            vowel_count = sum(1 for c in domain if c in vowels)
            consonant_count = sum(1 for c in domain if c in consonants)
            
            # High consonant to vowel ratio might indicate DGA
            if consonant_count > vowel_count * 3:
                return True
        
        return False