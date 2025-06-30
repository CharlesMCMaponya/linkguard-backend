from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import re
import logging
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from starlette.responses import JSONResponse

app = FastAPI()

# Basic CORS setup (adjust allow_origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change "*" to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(level=logging.INFO)

# Request model
class UrlInput(BaseModel):
    url: str

# Rate limiting (basic in-memory)
request_counts = {}
RATE_LIMIT = 5  # Max 5 requests
TIME_WINDOW = 60  # In seconds

from time import time

def is_rate_limited(ip: str):
    now = time()
    if ip not in request_counts:
        request_counts[ip] = []
    request_counts[ip] = [t for t in request_counts[ip] if now - t < TIME_WINDOW]
    if len(request_counts[ip]) >= RATE_LIMIT:
        return True
    request_counts[ip].append(now)
    return False

# Analyze endpoint
@app.post("/analyze")
async def analyze_link(data: UrlInput, request: Request):
    client_ip = request.client.host
    if is_rate_limited(client_ip):
        return JSONResponse(status_code=HTTP_429_TOO_MANY_REQUESTS, content={"detail": "Too many requests. Try again later."})

    url = data.url.strip()

    # Basic regex and keyword filtering
    red_flags = []
    score = 100
    category = "General"
    description = "This URL seems safe."

    if not re.match(r'^https?://', url):
        red_flags.append("Invalid URL format")
        score -= 20

    scam_keywords = ["free", "win", "login", "verify", "claim", "bonus"]
    if any(word in url.lower() for word in scam_keywords):
        red_flags.append("Suspicious keyword detected")
        score -= 30
        category = "Phishing"
        description = "Contains scam-related terms."

    if any(ext in url.lower() for ext in [".xyz", ".top", ".tk"]):
        red_flags.append("Unusual domain extension")
        score -= 20

    if "gov.za" not in url and ("sassa" in url or "nsfas" in url):
        red_flags.append("Pretending to be SA gov services")
        score -= 30
        category = "Impersonation"
        description = "May be impersonating South African institutions."

    status = "Safe"
    if score < 50:
        status = "Dangerous"
    elif score < 80:
        status = "Suspicious"

    # Logging the scan
    logging.info(f"Scanned by {client_ip}: {url} → {status} ({score})")

    return {
        "score": max(score, 0),
        "status": status,
        "redFlags": red_flags or ["No red flags found"],
        "category": category,
        "description": description
    }
