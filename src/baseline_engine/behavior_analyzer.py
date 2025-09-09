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

# Machine Learning imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not installed. ML-based anomaly detection disabled.")

class BaselineEngine:
    """Machine learning based baseline and anomaly detection"""
    
    def __init__(self, config: Dict[str, Any], data_callback: Callable, shutdown_event: threading.Event):
        self.config = config
        self.data_callback = data_callback
        self.shutdown_event = shutdown_event
        
        # Configuration
        self.learning_period_days = config.get('learning_period_days', 7)
        self.update_interval_hours = config.get('update_interval_hours', 24)
        self.anomaly_threshold = config.get('anomaly_threshold', 0.95)
        self.features = config.get('features', ['network_traffic', 'process_activity', 'file_access'])
        
        # Data storage
        self.data_path = Path("data/baselines")
        self.data_path.mkdir(parents=True, exist_ok=True)
        self.db_path = Path("data/baseline_data.db")
        
        # ML models
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        
        # Data collection
        self.data_buffer = defaultdict(deque)
        self.buffer_max_size = 10000
        
        self.logger = self._setup_logger()
        self.init_database()
    
    def _setup_logger(self):
        import logging
        return logging.getLogger('BaselineEngine')
    
    def init_database(self):
        """Initialize database for baseline data"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                feature_type TEXT NOT NULL,
                feature_data TEXT NOT NULL,
                is_anomaly BOOLEAN DEFAULT FALSE,
                anomaly_score REAL,
                model_version TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT UNIQUE NOT NULL,
                model_version TEXT NOT NULL,
                training_data_size INTEGER,
                training_timestamp TEXT,
                accuracy_score REAL,
                model_path TEXT
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_baseline_timestamp ON baseline_data(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_baseline_feature_type ON baseline_data(feature_type)')
        
        conn.commit()
        conn.close()
    
    def collect_network_features(self, network_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from network data"""
        features = {}
        
        # Basic traffic features
        features['packet_rate'] = network_data.get('packet_count', 0)
        features['byte_rate'] = network_data.get('total_bytes', 0)
        features['unique_sources'] = network_data.get('unique_source_ips', 0)
        features['unique_destinations'] = len(network_data.get('destinations', []))
        
        # Protocol distribution
        protocols = network_data.get('protocols', {})
        total_packets = sum(protocols.values()) if protocols else 1
        features['tcp_ratio'] = protocols.get('TCP', 0) / total_packets
        features['udp_ratio'] = protocols.get('UDP', 0) / total_packets
        features['icmp_ratio'] = protocols.get('ICMP', 0) / total_packets
        
        # Port distribution
        ports = network_data.get('destination_ports', {})
        common_ports = [80, 443, 53, 22, 21, 25]
        features['common_port_ratio'] = sum(ports.get(str(port), 0) for port in common_ports) / total_packets
        
        # Temporal features
        current_hour = datetime.now().hour
        features['hour_of_day'] = current_hour
        features['is_business_hours'] = 1 if 9 <= current_hour <= 17 else 0
        features['is_weekend'] = 1 if datetime.now().weekday() >= 5 else 0
        
        return features
    
    def collect_process_features(self, process_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from process data"""
        features = {}
        
        # Process count features
        processes = process_data.get('processes', [])
        features['total_processes'] = len(processes)
        features['unique_users'] = len(set(p.get('username') for p in processes if p.get('username')))
        
        # Resource usage features
        features['avg_cpu_usage'] = np.mean([p.get('cpu_percent', 0) for p in processes])
        features['max_cpu_usage'] = max([p.get('cpu_percent', 0) for p in processes], default=0)
        features['avg_memory_usage'] = np.mean([p.get('memory_percent', 0) for p in processes])
        features['max_memory_usage'] = max([p.get('memory_percent', 0) for p in processes], default=0)
        
        # Process types
        system_processes = sum(1 for p in processes if self._is_system_process(p.get('name', '')))
        features['system_process_ratio'] = system_processes / len(processes) if processes else 0
        
        # Execution paths
        temp_processes = sum(1 for p in processes if '/tmp/' in p.get('exe', ''))
        features['temp_process_ratio'] = temp_processes / len(processes) if processes else 0
        
        return features
    
    def collect_file_features(self, file_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from file system data"""
        features = {}
        
        # File operation counts
        features['file_creates'] = file_data.get('creates', 0)
        features['file_modifies'] = file_data.get('modifies', 0)
        features['file_deletes'] = file_data.get('deletes', 0)
        features['file_moves'] = file_data.get('moves', 0)
        
        # File type distribution
        file_types = file_data.get('file_types', {})
        total_files = sum(file_types.values()) if file_types else 1
        features['executable_ratio'] = file_types.get('executable', 0) / total_files
        features['config_ratio'] = file_types.get('config', 0) / total_files
        features['log_ratio'] = file_types.get('log', 0) / total_files
        
        # Directory activity
        directories = file_data.get('directories', {})
        features['system_dir_activity'] = directories.get('/etc', 0) + directories.get('/usr', 0)
        features['user_dir_activity'] = directories.get('/home', 0)
        features['temp_dir_activity'] = directories.get('/tmp', 0) + directories.get('/var/tmp', 0)
        
        return features
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if process is a system process"""
        system_processes = [
            'systemd', 'kernel', 'kthread', 'migration', 'rcu_gp',
            'watchdog', 'sshd', 'dbus', 'NetworkManager', 'cron'
        ]
        return any(sys_proc in process_name.lower() for sys_proc in system_processes)
    
    def train_models(self):
        """Train anomaly detection models"""
        if not ML_AVAILABLE:
            self.logger.warning("ML not available, skipping model training")
            return
        
        self.logger.info("Training baseline models...")
        
        try:
            for feature_type in self.features:
                self._train_feature_model(feature_type)
            
            self.logger.info("Model training completed")
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
    
    def _train_feature_model(self, feature_type: str):
        """Train model for specific feature type"""
        # Get training data
        training_data = self._get_training_data(feature_type)
        
        if len(training_data) < 100:
            self.logger.warning(f"Insufficient training data for {feature_type}: {len(training_data)}")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(training_data)
        
        # Feature scaling
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df.select_dtypes(include=[np.number]))
        
        # Train Isolation Forest
        model = IsolationForest(
            contamination=1 - self.anomaly_threshold,
            random_state=42,
            n_estimators=100
        )
        model.fit(scaled_data)
        
        # Store model and scaler
        self.models[feature_type] = model
        self.scalers[feature_type] = scaler
        
        # Save to disk
        model_path = self.data_path / f"{feature_type}_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': model,
                'scaler': scaler,
                'feature_columns': df.select_dtypes(include=[np.number]).columns.tolist(),
                'training_size': len(training_data),
                'training_timestamp': datetime.now().isoformat()
            }, f)
        
        # Update metadata
        self._update_model_metadata(feature_type, model_path, len(training_data))
        
        self.logger.info(f"Trained {feature_type} model with {len(training_data)} samples")
    
    def _get_training_data(self, feature_type: str) -> List[Dict[str, Any]]:
        """Get training data for feature type"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Get data from learning period
        cutoff_date = datetime.now() - timedelta(days=self.learning_period_days)
        
        cursor.execute('''
            SELECT feature_data FROM baseline_data 
            WHERE feature_type = ? AND timestamp > ? AND is_anomaly = FALSE
        ''', (feature_type, cutoff_date.isoformat()))
        
        training_data = []
        for row in cursor.fetchall():
            try:
                data = json.loads(row[0])
                training_data.append(data)
            except json.JSONDecodeError:
                continue
        
        conn.close()
        return training_data
    
    def _update_model_metadata(self, model_name: str, model_path: Path, training_size: int):
        """Update model metadata in database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO model_metadata 
            (model_name, model_version, training_data_size, training_timestamp, model_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            model_name,
            "1.0",
            training_size,
            datetime.now().isoformat(),
            str(model_path)
        ))
        
        conn.commit()
        conn.close()
    
    def detect_anomalies(self, feature_type: str, features: Dict[str, float]) -> tuple:
        """Detect anomalies in features"""
        if not ML_AVAILABLE or feature_type not in self.models:
            return False, 0.0
        
        try:
            model = self.models[feature_type]
            scaler = self.scalers[feature_type]
            
            # Convert features to array
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            scaled_features = scaler.transform(feature_array)
            
            # Predict anomaly
            anomaly_prediction = model.predict(scaled_features)[0]
            anomaly_score = model.decision_function(scaled_features)[0]
            
            is_anomaly = anomaly_prediction == -1
            confidence = abs(anomaly_score)
            
            return is_anomaly, confidence
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            return False, 0.0
    
    def process_data(self, data_type: str, data: Dict[str, Any]):
        """Process incoming data and detect anomalies"""
        try:
            # Extract features based on data type
            if data_type == 'network':
                features = self.collect_network_features(data)
            elif data_type == 'process':
                features = self.collect_process_features(data)
            elif data_type == 'file':
                features = self.collect_file_features(data)
            else:
                self.logger.warning(f"Unknown data type: {data_type}")
                return
            
            # Store features
            self._store_baseline_data(data_type, features)
            
            # Detect anomalies if model exists
            if data_type in self.models:
                is_anomaly, confidence = self.detect_anomalies(data_type, features)
                
                if is_anomaly:
                    self._handle_anomaly(data_type, features, confidence, data)
            
            # Add to data buffer
            self.data_buffer[data_type].append({
                'timestamp': datetime.now().isoformat(),
                'features': features,
                'raw_data': data
            })
            
            # Maintain buffer size
            if len(self.data_buffer[data_type]) > self.buffer_max_size:
                self.data_buffer[data_type].popleft()
                
        except Exception as e:
            self.logger.error(f"Error processing {data_type} data: {e}")
    
    def _store_baseline_data(self, feature_type: str, features: Dict[str, float]):
        """Store baseline data in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO baseline_data 
                (timestamp, feature_type, feature_data)
                VALUES (?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                feature_type,
                json.dumps(features)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing baseline data: {e}")
    
    def _handle_anomaly(self, data_type: str, features: Dict[str, float], confidence: float, raw_data: Dict[str, Any]):
        """Handle detected anomaly"""
        anomaly_info = {
            'timestamp': datetime.now().isoformat(),
            'data_type': data_type,
            'features': features,
            'confidence': confidence,
            'raw_data': raw_data
        }
        
        # Send to correlation engine
        self.data_callback(anomaly_info)
        
        self.logger.warning(f"Anomaly detected in {data_type} data (confidence: {confidence:.2f})")
    
    def start(self):
        """Start baseline engine"""
        self.logger.info("Starting baseline engine...")
        
        # Load existing models
        self._load_models()
        
        # Start periodic training
        training_thread = threading.Thread(
            target=self._periodic_training,
            daemon=True
        )
        training_thread.start()
        
        # Main processing loop
        while not self.shutdown_event.is_set():
            try:
                # Process buffered data
                self._process_buffer()
                
                # Wait before next iteration
                self.shutdown_event.wait(60)  # Process every minute
                
            except Exception as e:
                self.logger.error(f"Error in baseline engine main loop: {e}")
                time.sleep(60)
    
    def _load_models(self):
        """Load existing models from disk"""
        for feature_type in self.features:
            model_path = self.data_path / f"{feature_type}_model.pkl"
            
            if model_path.exists():
                try:
                    with open(model_path, 'rb') as f:
                        model_data = pickle.load(f)
                    
                    self.models[feature_type] = model_data['model']
                    self.scalers[feature_type] = model_data['scaler']
                    
                    self.logger.info(f"Loaded {feature_type} model")
                    
                except Exception as e:
                    self.logger.error(f"Error loading {feature_type} model: {e}")
    
    def _periodic_training(self):
        """Periodic model retraining"""
        while not self.shutdown_event.is_set():
            try:
                # Wait for training interval
                wait_seconds = self.update_interval_hours * 3600
                if self.shutdown_event.wait(wait_seconds):
                    break
                
                # Retrain models
                self.train_models()
                
            except Exception as e:
                self.logger.error(f"Error in periodic training: {e}")
    
    def _process_buffer(self):
        """Process data in buffer"""
        # This can be used for batch processing or additional analysis
        for data_type, buffer in self.data_buffer.items():
            if len(buffer) >= 100:  # Process when we have enough data
                # Perform batch analysis
                self._batch_analysis(data_type, list(buffer))

    def _batch_analysis(self, data_type: str, data_batch: List[Dict[str, Any]]):
        """Perform batch analysis on data"""
        if not ML_AVAILABLE:
            return
        
        try:
            # Extract features from batch
            features_batch = []
            for item in data_batch:
                features_batch.append(item['features'])
            
            if not features_batch:
                return
            
            # Convert to DataFrame for analysis
            df = pd.DataFrame(features_batch)
            
            # Perform clustering analysis
            if len(df) >= 20:  # Need minimum samples for clustering
                self._cluster_analysis(data_type, df, data_batch)
                
        except Exception as e:
            self.logger.error(f"Error in batch analysis: {e}")
    
    def _cluster_analysis(self, data_type: str, features_df: pd.DataFrame, data_batch: List[Dict[str, Any]]):
        """Perform cluster analysis to find patterns"""
        try:
            # Standardize features
            scaler = StandardScaler()
            scaled_features = scaler.fit_transform(features_df.select_dtypes(include=[np.number]))
            
            # Apply DBSCAN clustering
            clustering = DBSCAN(eps=0.5, min_samples=3)
            cluster_labels = clustering.fit_predict(scaled_features)
            
            # Find outliers (noise points)
            outlier_indices = np.where(cluster_labels == -1)[0]
            
            # Report outliers
            for idx in outlier_indices:
                outlier_data = data_batch[idx]
                self.logger.info(f"Cluster outlier detected in {data_type}: {outlier_data['timestamp']}")
                
                # Could generate alerts for significant outliers
                
        except Exception as e:
            self.logger.error(f"Error in cluster analysis: {e}")
