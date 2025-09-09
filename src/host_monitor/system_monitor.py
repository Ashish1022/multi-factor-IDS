import os
import sys
import time
import psutil
import hashlib
import threading
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, Callable, List, Set
from collections import defaultdict, deque
from pathlib import Path
import json

# File monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, PatternMatchingEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog not installed. File monitoring will be limited.")

class HostMonitor:
    """Host-based monitoring and analysis"""
    
    def __init__(self, config: Dict[str, Any], alert_callback: Callable, shutdown_event: threading.Event):
        self.config = config
        self.alert_callback = alert_callback
        self.shutdown_event = shutdown_event
        
        # Configuration
        self.scan_interval = config.get('scan_interval', 30)
        self.monitor_processes = config.get('monitor_processes', True)
        self.monitor_files = config.get('monitor_files', True)
        self.monitor_network = config.get('monitor_network', True)
        self.watched_directories = config.get('watched_directories', ['/etc', '/home', '/var/log'])
        
        # Monitoring components
        self.process_monitor = ProcessMonitor(self.alert_callback)
        self.file_monitor = FileMonitor(self.watched_directories, self.alert_callback)
        self.network_monitor = NetworkConnectionMonitor(self.alert_callback)
        self.system_monitor = SystemResourceMonitor(self.alert_callback)
        
        # Database for storing events
        self.db_path = Path("data/host_events.db")
        self.init_database()
        
        # Baseline tracking
        self.baseline_processes = set()
        self.baseline_network_connections = set()
        self.baseline_system_state = {}
        
        self.logger = self._setup_logger()
        
        # Threading
        self.monitoring_threads = []
    
    def _setup_logger(self):
        """Setup component logger"""
        import logging
        logger = logging.getLogger('HostMonitor')
        return logger
    
    def init_database(self):
        """Initialize SQLite database for host events"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Host events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                details TEXT,
                file_path TEXT,
                process_name TEXT,
                process_id INTEGER,
                user TEXT,
                suspicious BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # File integrity table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_integrity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                permissions TEXT,
                owner TEXT,
                last_modified TEXT,
                last_checked TEXT
            )
        ''')
        
        # Process baseline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL,
                executable_path TEXT,
                command_line TEXT,
                user TEXT,
                first_seen TEXT,
                last_seen TEXT,
                frequency INTEGER DEFAULT 1
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_timestamp ON host_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_type ON host_events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON file_integrity(file_path)')
        
        conn.commit()
        conn.close()
    
    def establish_baseline(self):
        """Establish baseline for normal system behavior"""
        self.logger.info("Establishing host baseline...")
        
        try:
            # Process baseline
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    info = proc.info
                    if info['name']:
                        self.baseline_processes.add(info['name'])
                        self._store_process_baseline(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Network connections baseline
            for conn in psutil.net_connections():
                if conn.status == psutil.CONN_ESTABLISHED:
                    conn_tuple = (conn.laddr, conn.raddr, conn.status)
                    self.baseline_network_connections.add(str(conn_tuple))
            
            # System resources baseline
            self.baseline_system_state = {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {p.mountpoint: psutil.disk_usage(p.mountpoint).percent 
                              for p in psutil.disk_partitions()},
                'boot_time': psutil.boot_time()
            }
            
            # File integrity baseline
            if self.monitor_files:
                self._establish_file_baseline()
            
            self.logger.info(f"Baseline established: {len(self.baseline_processes)} processes, "
                           f"{len(self.baseline_network_connections)} connections")
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {e}")
    
    def _establish_file_baseline(self):
        """Establish baseline for critical files"""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/hosts',
            '/etc/ssh/sshd_config',
            '/etc/crontab',
            '/boot/grub/grub.cfg'
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    self._calculate_file_integrity(file_path, is_baseline=True)
                except Exception as e:
                    self.logger.error(f"Error calculating integrity for {file_path}: {e}")
    
    def _calculate_file_integrity(self, file_path: str, is_baseline: bool = False):
        """Calculate and store file integrity information"""
        try:
            stat_info = os.stat(file_path)
            
            # Calculate file hash
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            # Get file metadata
            file_info = {
                'file_path': file_path,
                'file_hash': file_hash,
                'file_size': stat_info.st_size,
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': stat_info.st_uid,
                'last_modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'last_checked': datetime.now().isoformat()
            }
            
            if is_baseline:
                self._store_file_integrity(file_info)
            else:
                return self._check_file_integrity(file_info)
                
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
            return False
    
    def _store_file_integrity(self, file_info: dict):
        """Store file integrity information"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO file_integrity 
                (file_path, file_hash, file_size, permissions, owner, 
                 last_modified, last_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_info['file_path'],
                file_info['file_hash'],
                file_info['file_size'],
                file_info['permissions'],
                file_info['owner'],
                file_info['last_modified'],
                file_info['last_checked']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing file integrity: {e}")
    
    def _check_file_integrity(self, current_info: dict) -> bool:
        """Check if file has been modified"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT file_hash, file_size, permissions, last_modified 
                FROM file_integrity 
                WHERE file_path = ?
            ''', (current_info['file_path'],))
            
            baseline = cursor.fetchone()
            conn.close()
            
            if not baseline:
                # New file detected
                self._generate_file_alert('NEW_FILE', current_info)
                self._store_file_integrity(current_info)
                return True
            
            baseline_hash, baseline_size, baseline_perms, baseline_modified = baseline
            
            # Check for modifications
            changes = []
            if current_info['file_hash'] != baseline_hash:
                changes.append('content')
            if current_info['file_size'] != baseline_size:
                changes.append('size')
            if current_info['permissions'] != baseline_perms:
                changes.append('permissions')
            if current_info['last_modified'] != baseline_modified:
                changes.append('timestamp')
            
            if changes:
                self._generate_file_alert('FILE_MODIFIED', current_info, changes)
                self._store_file_integrity(current_info)  # Update baseline
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking file integrity: {e}")
            return False
    
    def _store_process_baseline(self, proc_info: dict):
        """Store process baseline information"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO process_baseline 
                (process_name, executable_path, command_line, user, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                proc_info.get('name'),
                proc_info.get('exe'),
                ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else '',
                proc_info.get('username'),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            # Update frequency and last seen
            cursor.execute('''
                UPDATE process_baseline 
                SET frequency = frequency + 1, last_seen = ?
                WHERE process_name = ?
            ''', (datetime.now().isoformat(), proc_info.get('name')))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing process baseline: {e}")
    
    def _generate_file_alert(self, alert_type: str, file_info: dict, changes: List[str] = None):
        """Generate file-related alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'HostMonitor',
            'alert_type': alert_type,
            'severity': 'HIGH' if 'shadow' in file_info['file_path'] or 'passwd' in file_info['file_path'] else 'MEDIUM',
            'file_path': file_info['file_path'],
            'description': f"File {alert_type.lower().replace('_', ' ')}: {file_info['file_path']}",
            'changes': changes or [],
            'raw_data': file_info
        }
        
        self.alert_callback(alert)
        self._store_host_event(alert_type, 'FileMonitor', alert['severity'], 
                              alert['description'], json.dumps(file_info), 
                              file_path=file_info['file_path'])
    
    def _store_host_event(self, event_type: str, source: str, severity: str, 
                         description: str, details: str, **kwargs):
        """Store host event in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO host_events 
                (timestamp, event_type, source, severity, description, details,
                 file_path, process_name, process_id, user, suspicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                source,
                severity,
                description,
                details,
                kwargs.get('file_path'),
                kwargs.get('process_name'),
                kwargs.get('process_id'),
                kwargs.get('user'),
                kwargs.get('suspicious', severity in ['HIGH', 'CRITICAL'])
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing host event: {e}")
    
    def start(self):
        """Start host monitoring"""
        self.logger.info("Starting host monitor...")
        
        # Establish baseline first
        self.establish_baseline()
        
        # Start monitoring threads
        if self.monitor_processes:
            process_thread = threading.Thread(
                target=self.process_monitor.start_monitoring,
                args=(self.shutdown_event,),
                daemon=True
            )
            process_thread.start()
            self.monitoring_threads.append(process_thread)
        
        if self.monitor_files and WATCHDOG_AVAILABLE:
            file_thread = threading.Thread(
                target=self.file_monitor.start_monitoring,
                args=(self.shutdown_event,),
                daemon=True
            )
            file_thread.start()
            self.monitoring_threads.append(file_thread)
        
        if self.monitor_network:
            network_thread = threading.Thread(
                target=self.network_monitor.start_monitoring,
                args=(self.shutdown_event,),
                daemon=True
            )
            network_thread.start()
            self.monitoring_threads.append(network_thread)
        
        # Start system resource monitoring
        system_thread = threading.Thread(
            target=self.system_monitor.start_monitoring,
            args=(self.shutdown_event,),
            daemon=True
        )
        system_thread.start()
        self.monitoring_threads.append(system_thread)
        
        # Main monitoring loop
        self._main_monitoring_loop()
    
    def _main_monitoring_loop(self):
        """Main monitoring loop"""
        while not self.shutdown_event.is_set():
            try:
                # Periodic integrity checks
                if self.monitor_files:
                    self._run_integrity_checks()
                
                # Check for process anomalies
                if self.monitor_processes:
                    self._check_process_anomalies()
                
                # Wait for next scan
                self.shutdown_event.wait(self.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in main monitoring loop: {e}")
                time.sleep(10)
    
    def _run_integrity_checks(self):
        """Run periodic file integrity checks"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT file_path FROM file_integrity')
            monitored_files = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            for file_path in monitored_files:
                if os.path.exists(file_path):
                    self._calculate_file_integrity(file_path)
                else:
                    # File was deleted
                    self._generate_file_alert('FILE_DELETED', {'file_path': file_path})
                    
        except Exception as e:
            self.logger.error(f"Error running integrity checks: {e}")
    
    def _check_process_anomalies(self):
        """Check for process anomalies"""
        try:
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    info = proc.info
                    if info['name']:
                        current_processes.add(info['name'])
                        
                        # Check for new processes
                        if info['name'] not in self.baseline_processes:
                            self._generate_process_alert('NEW_PROCESS', info)
                            
                        # Check for suspicious processes
                        if self._is_suspicious_process(info):
                            self._generate_process_alert('SUSPICIOUS_PROCESS', info)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for disappeared processes (optional)
            disappeared = self.baseline_processes - current_processes
            for proc_name in list(disappeared)[:5]:  # Limit to avoid spam
                self.logger.debug(f"Process no longer running: {proc_name}")
                
        except Exception as e:
            self.logger.error(f"Error checking process anomalies: {e}")
    
    def _is_suspicious_process(self, proc_info: dict) -> bool:
        """Check if process is suspicious"""
        suspicious_names = [
            'nc', 'netcat', 'ncat',  # Network tools
            'python', 'perl', 'ruby',  # Scripting (if unexpected)
            'wget', 'curl',  # Download tools
            'base64', 'uuencode',  # Encoding tools
            'dd'  # Data dumping
        ]
        
        suspicious_paths = [
            '/tmp/',
            '/var/tmp/',
            '/dev/shm/',
            '/home/*/Desktop/'
        ]
        
        name = proc_info.get('name', '').lower()
        exe_path = proc_info.get('exe', '') or ''
        
        # Check suspicious names
        if name in suspicious_names:
            return True
        
        # Check suspicious paths
        for path in suspicious_paths:
            if path.replace('*', '') in exe_path:
                return True
        
        # Check for processes running from tmp directories
        if '/tmp/' in exe_path or '/var/tmp/' in exe_path:
            return True
        
        return False
    
    def _generate_process_alert(self, alert_type: str, proc_info: dict):
        """Generate process-related alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'HostMonitor',
            'alert_type': alert_type,
            'severity': 'HIGH' if alert_type == 'SUSPICIOUS_PROCESS' else 'MEDIUM',
            'process_name': proc_info.get('name'),
            'process_id': proc_info.get('pid'),
            'executable_path': proc_info.get('exe'),
            'command_line': ' '.join(proc_info.get('cmdline', [])),
            'user': proc_info.get('username'),
            'description': f"{alert_type.replace('_', ' ').title()}: {proc_info.get('name')}",
            'raw_data': proc_info
        }
        
        self.alert_callback(alert)
        self._store_host_event(alert_type, 'ProcessMonitor', alert['severity'],
                              alert['description'], json.dumps(proc_info),
                              process_name=proc_info.get('name'),
                              process_id=proc_info.get('pid'),
                              user=proc_info.get('username'))

# =============================================================================
# Process Monitor
# =============================================================================

class ProcessMonitor:
    """Monitor system processes"""
    
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.logger = self._setup_logger()
        self.previous_processes = {}
        
    def _setup_logger(self):
        import logging
        return logging.getLogger('ProcessMonitor')
    
    def start_monitoring(self, shutdown_event: threading.Event):
        """Start process monitoring"""
        self.logger.info("Starting process monitoring...")
        
        while not shutdown_event.is_set():
            try:
                self._scan_processes()
                shutdown_event.wait(10)  # Scan every 10 seconds
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                time.sleep(30)
    
    def _scan_processes(self):
        """Scan current processes"""
        current_processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                current_processes[info['pid']] = info
                
                # Check for high resource usage
                if info['cpu_percent'] and info['cpu_percent'] > 90:
                    self._generate_alert('HIGH_CPU_USAGE', info)
                
                if info['memory_percent'] and info['memory_percent'] > 90:
                    self._generate_alert('HIGH_MEMORY_USAGE', info)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check for new processes
        new_processes = set(current_processes.keys()) - set(self.previous_processes.keys())
        for pid in new_processes:
            proc_info = current_processes[pid]
            if self._is_interesting_process(proc_info):
                self._generate_alert('NEW_PROCESS', proc_info)
        
        self.previous_processes = current_processes
    
    def _is_interesting_process(self, proc_info: dict) -> bool:
        """Check if process is interesting enough to alert on"""
        # Skip system processes and common applications
        boring_processes = [
            'systemd', 'kthreadd', 'rcu_gp', 'rcu_par_gp', 'migration',
            'ksoftirqd', 'watchdog', 'sshd', 'dbus', 'NetworkManager'
        ]
        
        name = proc_info.get('name', '').lower()
        return name not in boring_processes
    
    def _generate_alert(self, alert_type: str, proc_info: dict):
        """Generate process alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'ProcessMonitor',
            'alert_type': alert_type,
            'severity': 'MEDIUM',
            'process_name': proc_info.get('name'),
            'process_id': proc_info.get('pid'),
            'description': f"{alert_type.replace('_', ' ').title()}: {proc_info.get('name')}",
            'raw_data': proc_info
        }
        
        self.alert_callback(alert)

# =============================================================================
# File Monitor
# =============================================================================

class FileMonitor:
    """Monitor file system changes"""
    
    def __init__(self, watched_directories: List[str], alert_callback: Callable):
        self.watched_directories = watched_directories
        self.alert_callback = alert_callback
        self.logger = self._setup_logger()
        self.observer = None
        
    def _setup_logger(self):
        import logging
        return logging.getLogger('FileMonitor')
    
    def start_monitoring(self, shutdown_event: threading.Event):
        """Start file system monitoring"""
        if not WATCHDOG_AVAILABLE:
            self.logger.warning("Watchdog not available, file monitoring disabled")
            return
        
        self.logger.info(f"Starting file monitoring for: {self.watched_directories}")
        
        try:
            self.observer = Observer()
            
            for directory in self.watched_directories:
                if os.path.exists(directory):
                    event_handler = SecurityFileHandler(self.alert_callback)
                    self.observer.schedule(event_handler, directory, recursive=True)
                    self.logger.info(f"Monitoring directory: {directory}")
                else:
                    self.logger.warning(f"Directory not found: {directory}")
            
            self.observer.start()
            
            # Wait for shutdown
            while not shutdown_event.is_set():
                shutdown_event.wait(1)
            
            self.observer.stop()
            self.observer.join()
            
        except Exception as e:
            self.logger.error(f"File monitoring error: {e}")

class SecurityFileHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.logger = self._setup_logger()
        
        # Ignore patterns
        self.ignore_patterns = [
            '*.tmp', '*.log', '*.swp', '*.swap', '*~',
            '*.pid', '*.lock', '.git/*', '__pycache__/*'
        ]
        
        # Critical files to monitor
        self.critical_files = [
            '/etc/passwd', '/etc/shadow', '/etc/group',
            '/etc/sudoers', '/etc/hosts', '/etc/ssh/sshd_config'
        ]
    
    def _setup_logger(self):
        import logging
        return logging.getLogger('SecurityFileHandler')
    
    def _should_ignore(self, file_path: str) -> bool:
        """Check if file should be ignored"""
        import fnmatch
        
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and not self._should_ignore(event.src_path):
            severity = 'CRITICAL' if event.src_path in self.critical_files else 'MEDIUM'
            self._generate_alert('FILE_MODIFIED', event.src_path, severity)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and not self._should_ignore(event.src_path):
            # New files in system directories are suspicious
            if any(event.src_path.startswith(d) for d in ['/etc/', '/usr/bin/', '/usr/sbin/']):
                self._generate_alert('FILE_CREATED', event.src_path, 'HIGH')
            else:
                self._generate_alert('FILE_CREATED', event.src_path, 'LOW')
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory and not self._should_ignore(event.src_path):
            severity = 'CRITICAL' if event.src_path in self.critical_files else 'MEDIUM'
            self._generate_alert('FILE_DELETED', event.src_path, severity)
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if not event.is_directory:
            if not self._should_ignore(event.src_path) or not self._should_ignore(event.dest_path):
                self._generate_alert('FILE_MOVED', f"{event.src_path} -> {event.dest_path}", 'MEDIUM')
    
    def _generate_alert(self, alert_type: str, file_path: str, severity: str):
        """Generate file system alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'FileMonitor',
            'alert_type': alert_type,
            'severity': severity,
            'file_path': file_path,
            'description': f"{alert_type.replace('_', ' ').title()}: {file_path}",
            'raw_data': {'file_path': file_path, 'event_type': alert_type}
        }
        
        self.alert_callback(alert)
        self.logger.info(f"File alert: {alert_type} - {file_path}")

# =============================================================================
# Network Connection Monitor
# =============================================================================

class NetworkConnectionMonitor:
    """Monitor network connections"""
    
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.logger = self._setup_logger()
        self.previous_connections = set()
        
        # Suspicious ports
        self.suspicious_ports = {
            1337, 31337, 4444, 5555, 6666, 12345, 54321,  # Common backdoor ports
            6667, 6668, 6669,  # IRC
            1234, 3389, 5900,  # Remote access
        }
        
    def _setup_logger(self):
        import logging
        return logging.getLogger('NetworkConnectionMonitor')
    
    def start_monitoring(self, shutdown_event: threading.Event):
        """Start network connection monitoring"""
        self.logger.info("Starting network connection monitoring...")
        
        while not shutdown_event.is_set():
            try:
                self._scan_connections()
                shutdown_event.wait(15)  # Scan every 15 seconds
            except Exception as e:
                self.logger.error(f"Network connection monitoring error: {e}")
                time.sleep(30)
    
    def _scan_connections(self):
        """Scan current network connections"""
        current_connections = set()
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED:
                    conn_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    conn_str = f"{conn_info['local_addr']} -> {conn_info['remote_addr']}"
                    current_connections.add(conn_str)
                    
                    # Check for suspicious connections
                    if conn.raddr and conn.raddr.port in self.suspicious_ports:
                        self._generate_alert('SUSPICIOUS_CONNECTION', conn_info)
                    
                    # Check for new connections
                    if conn_str not in self.previous_connections:
                        self._check_new_connection(conn_info)
            
            self.previous_connections = current_connections
            
        except Exception as e:
            self.logger.error(f"Error scanning connections: {e}")
    
    def _check_new_connection(self, conn_info: dict):
        """Check if new connection is suspicious"""
        # Get process info if available
        if conn_info['pid']:
            try:
                proc = psutil.Process(conn_info['pid'])
                proc_name = proc.name()
                
                # Alert on suspicious process connections
                suspicious_processes = ['nc', 'netcat', 'python', 'perl', 'ruby']
                if proc_name.lower() in suspicious_processes:
                    self._generate_alert('SUSPICIOUS_PROCESS_CONNECTION', {
                        **conn_info,
                        'process_name': proc_name
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    
    def _generate_alert(self, alert_type: str, conn_info: dict):
        """Generate network connection alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'NetworkConnectionMonitor',
            'alert_type': alert_type,
            'severity': 'HIGH' if 'SUSPICIOUS' in alert_type else 'MEDIUM',
            'local_address': conn_info.get('local_addr'),
            'remote_address': conn_info.get('remote_addr'),
            'process_id': conn_info.get('pid'),
            'process_name': conn_info.get('process_name'),
            'description': f"{alert_type.replace('_', ' ').title()}: {conn_info.get('remote_addr')}",
            'raw_data': conn_info
        }
        
        self.alert_callback(alert)

# =============================================================================
# System Resource Monitor
# =============================================================================

class SystemResourceMonitor:
    """Monitor system resource usage"""
    
    def __init__(self, alert_callback: Callable):
        self.alert_callback = alert_callback
        self.logger = self._setup_logger()
        
        # Thresholds
        self.cpu_threshold = 90.0
        self.memory_threshold = 90.0
        self.disk_threshold = 95.0
        self.load_threshold = 10.0
        
    def _setup_logger(self):
        import logging
        return logging.getLogger('SystemResourceMonitor')
    
    def start_monitoring(self, shutdown_event: threading.Event):
        """Start system resource monitoring"""
        self.logger.info("Starting system resource monitoring...")
        
        while not shutdown_event.is_set():
            try:
                self._check_resources()
                shutdown_event.wait(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"System resource monitoring error: {e}")
                time.sleep(60)
    
    def _check_resources(self):
        """Check system resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.cpu_threshold:
                self._generate_alert('HIGH_CPU_USAGE', {
                    'cpu_percent': cpu_percent,
                    'threshold': self.cpu_threshold
                })
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > self.memory_threshold:
                self._generate_alert('HIGH_MEMORY_USAGE', {
                    'memory_percent': memory.percent,
                    'threshold': self.memory_threshold,
                    'available_mb': memory.available // 1024 // 1024
                })
            
            # Disk usage
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage.percent > self.disk_threshold:
                        self._generate_alert('HIGH_DISK_USAGE', {
                            'mountpoint': partition.mountpoint,
                            'usage_percent': usage.percent,
                            'threshold': self.disk_threshold,
                            'free_gb': usage.free // 1024 // 1024 // 1024
                        })
                except PermissionError:
                    continue
            
            # Load average (Linux only)
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()[0]  # 1-minute load average
                if load_avg > self.load_threshold:
                    self._generate_alert('HIGH_LOAD_AVERAGE', {
                        'load_average': load_avg,
                        'threshold': self.load_threshold
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking resources: {e}")
    
    def _generate_alert(self, alert_type: str, resource_info: dict):
        """Generate system resource alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'component': 'SystemResourceMonitor',
            'alert_type': alert_type,
            'severity': 'HIGH',
            'description': f"{alert_type.replace('_', ' ').title()}",
            'raw_data': resource_info
        }
        
        self.alert_callback(alert)