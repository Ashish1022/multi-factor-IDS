import pandas as pd
from pathlib import Path

# Paths
data_file = Path('machine-learning/model-data/processed/network_events_with_anomalies.csv')
output_file = Path('machine-learning/model-data/processed/network_events_timeseries.csv')

def main():
    df = pd.read_csv(data_file)
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Set timestamp as index
    df.set_index('timestamp', inplace=True)
    
    # Aggregate: count packets per minute
    ts = df.resample('1T').size().rename('packet_count')
    
    # Fill missing intervals with 0
    ts = ts.fillna(0)
    
    # Save to CSV
    output_file.parent.mkdir(parents=True, exist_ok=True)
    ts.to_csv(output_file, header=True)
    
    print(f"Time series data prepared and saved to {output_file}")

if __name__ == "__main__":
    main()
