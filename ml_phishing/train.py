import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import joblib

df = pd.read_csv("Phishing_Email.csv")
df = df.dropna(subset=["Email Text", "Email Type"])

X = df["Email Text"]
y = df["Email Type"].apply(lambda x: 1 if x == "Phishing Email" else 0)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

vectorizer = TfidfVectorizer(max_features=3000, stop_words="english")
X_train_vec = vectorizer.fit_transform(X_train)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Model trained and saved.")
print("Test accuracy:", model.score(vectorizer.transform(X_test), y_test))