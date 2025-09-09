import sqlite3
import pandas as pd
from pathlib import Path

# Path to the network events database
db_path = Path('data/network_events.db')

def load_network_events():
    conn = sqlite3.connect(str(db_path))
    query = "SELECT timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, suspicious, threat_type, severity FROM network_events"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def preprocess(df):
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Encode protocol (TCP, UDP, ICMP, etc.)
    df['protocol'] = df['protocol'].fillna('UNKNOWN')
    df = pd.get_dummies(df, columns=['protocol'])

    # Handle flags: presence/absence
    df['flags'] = df['flags'].fillna('')
    for flag in ['S', 'A', 'F', 'R', 'P']:  # Common TCP flags
        df[f'flag_{flag}'] = df['flags'].apply(lambda x: int(flag in x))

    # Encode suspicious
    df['suspicious'] = df['suspicious'].astype(int)

    # Fill missing ports with 0
    df['source_port'] = df['source_port'].fillna(0)
    df['dest_port'] = df['dest_port'].fillna(0)

    # Encode threat_type as categorical
    df['threat_type'] = df['threat_type'].fillna('NONE')
    df = pd.get_dummies(df, columns=['threat_type'])

    # Encode severity
    severity_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
    df['severity'] = df['severity'].map(severity_map).fillna(0)

    return df

def main():
    df = load_network_events()
    df = preprocess(df)
    print("Data loaded and preprocessed. Sample:")
    print(df.head())

    # Save to CSV for later ML tasks
    df.to_csv('machine-learning/model-data/processed/network_events_processed.csv', index=False)
    print("Preprocessed data saved to 'network_events_processed.csv'")

if __name__ == "__main__":
    main()
