from fastapi import FastAPI
from app.models import case
from app.database import engine
from app.api.router import api_router

# Create the database tables
case.Base.metadata.create_all(bind=engine)

import os
import logging
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    description="Backend API for email threat investigation and forensic intelligence.",
    version="1.0.0"
)

# Read FRONTEND_URL from environment for secure CORS, fallback to wildcard for dev
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Email Threat Intelligence Platform API"}
