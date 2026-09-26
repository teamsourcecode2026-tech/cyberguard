from dotenv import load_dotenv
import os
from pymongo import MongoClient

load_dotenv()

uri = os.getenv("MONGO_URI")
client = MongoClient(uri)

try:
    client.admin.command('ping')
    print("Connection successful! MongoDB is reachable.")
except Exception as e:
    print("Connection failed:", e)