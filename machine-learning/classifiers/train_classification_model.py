import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from pathlib import Path

# Paths
data_file = Path('machine-learning/model-data/processed/network_events_with_anomalies.csv')
model_file = Path('machine-learning/models/classification_model.pkl')

def load_data():
    df = pd.read_csv(data_file)
    print(f"Loaded {len(df)} records from {data_file}")
    return df

def train_classification_model(df):
    # Features and label
    features = df.drop(columns=['timestamp', 'source_ip', 'dest_ip', 'flags', 'threat_type_NONE', 'threat_type_UDP_FLOOD', 'anomaly'])
    label = df['threat_type_UDP_FLOOD'].astype(int)

    # Split into train/test sets
    X_train, X_test, y_train, y_test = train_test_split(features, label, test_size=0.3, random_state=42)

    # Train classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_file)
    print("Threat classification model trained and saved.")

def main():
    df = load_data()
    train_classification_model(df)

if __name__ == "__main__":
    main()
