from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import bcrypt
from datetime import datetime

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client["cyberguard"]
users = db["users"]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/register")
def register(data: RegisterRequest):
    existing = users.find_one({"username": data.username})
    if existing:
        return {"success": False, "message": "Username already exists"}

    hashed = bcrypt.hashpw(data.password.encode("utf-8"), bcrypt.gensalt())

    users.insert_one({
        "username": data.username,
        "password": hashed.decode("utf-8"),
        "created_at": str(datetime.now())
    })

    return {"success": True, "message": "Registered successfully"}


@app.post("/api/login")
def login(data: LoginRequest):
    user = users.find_one({"username": data.username})

    if not user:
        return {"success": False, "message": "User not found"}

    stored_hash = user["password"].encode("utf-8")
    entered_password = data.password.encode("utf-8")

    if not bcrypt.checkpw(entered_password, stored_hash):
        return {"success": False, "message": "Incorrect password"}

    return {"success": True, "message": "Login successful", "username": data.username}