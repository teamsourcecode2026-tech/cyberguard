import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib

df = pd.read_csv("login_logs.csv")

features = ["failed_attempts", "new_device", "unusual_time"]
X = df[features]

model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X)

joblib.dump(model, "anomaly_model.pkl")
print("Anomaly model trained and saved.")