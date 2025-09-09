import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from pathlib import Path

# Paths
data_file = Path('machine-learning/model-data/processed/network_events_processed.csv')
model_file = Path('machine-learning/models/anomaly_model.pkl')

def load_data():
    df = pd.read_csv(data_file)
    print(f"Loaded {len(df)} records from {data_file}")
    return df

def train_anomaly_model(df):
    # Features to use (exclude timestamp, IPs, flags used only for description)
    features = df.drop(columns=['timestamp', 'source_ip', 'dest_ip', 'flags', 'threat_type_NONE', 'threat_type_UDP_FLOOD'])
    
    # Fit Isolation Forest
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    
    # Save model
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_file)
    
    print("Anomaly detection model trained and saved.")

def predict_anomalies(df):
    features = df.drop(columns=['timestamp', 'source_ip', 'dest_ip', 'flags', 'threat_type_NONE', 'threat_type_UDP_FLOOD'])
    model = joblib.load(model_file)
    
    df['anomaly'] = model.predict(features)
    df['anomaly'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
    
    print(df[['timestamp', 'source_ip', 'dest_ip', 'anomaly']].head())
    return df

def main():
    df = load_data()
    train_anomaly_model(df)
    result = predict_anomalies(df)
    result.to_csv('machine-learning/model-data/processed/network_events_with_anomalies.csv', index=False)
    print("Results saved with anomaly labels.")

if __name__ == "__main__":
    main()
