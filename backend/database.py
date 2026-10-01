from dotenv import load_dotenv
import os
from pymongo import MongoClient

load_dotenv()

uri = os.getenv("MONGO_URI")

client = MongoClient(uri)

db = client["cyberguard"]

events = db["events"]

phishing_results = db["phishing_results"]

anomaly_results = db["anomaly_results"]

deepfake_results = db["deepfake_results"]

alerts = db["alerts"]

users = db["users"]