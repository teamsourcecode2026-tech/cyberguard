from dotenv import load_dotenv
import os
from pymongo import MongoClient

load_dotenv()

uri = os.getenv("MONGO_URI")
client = MongoClient(uri)
db = client["cyberguard"]  # this creates/uses a database named "cyberguard"

events = db["events"]
phishing_results = db["phishing_results"]
alerts = db["alerts"]