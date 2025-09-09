import pandas as pd
from pathlib import Path
import joblib
from statsmodels.tsa.arima.model import ARIMA

# Paths
data_file = Path('machine-learning/model-data/processed/network_events_timeseries.csv')
model_file = Path('machine-learning/models/forecasting_model.pkl')

def main():
    df = pd.read_csv(data_file, index_col='timestamp', parse_dates=True)
    print(f"Loaded {len(df)} time points.")

    # Train ARIMA model
    model = ARIMA(df['packet_count'], order=(1,1,1))  # Adjust p,d,q as needed
    model_fit = model.fit()
    
    # Save model
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_fit, model_file)
    
    print("Forecasting model trained and saved.")
    print(model_fit.summary())

if __name__ == "__main__":
    main()
