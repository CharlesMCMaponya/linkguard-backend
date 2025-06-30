from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend access (default: localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, change to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define expected request body
class UrlInput(BaseModel):
    url: str

@app.post("/analyze")
async def analyze_link(data: UrlInput):
    url = data.url.lower()
    red_flags = []
    score = 100
    category = "General"
    description = "This URL seems safe."

    # Red flag 1: Common scam keywords
    if any(word in url for word in ["free", "win", "login", "verify", "claim"]):
        red_flags.append("Suspicious keyword detected")
        score -= 30
        category = "Phishing"
        description = "Contains common scam-related terms."

    # Red flag 2: Suspicious domain endings
    if any(url.endswith(ext) or f".{ext}/" in url for ext in ["xyz", "top", "tk", "click"]):
        red_flags.append("Unusual domain extension")
        score -= 20

    # Red flag 3: Impersonating SA government
    if "gov.za" not in url and "gov" in url:
        red_flags.append("Pretending to be a government domain")
        score -= 25
        category = "Impersonation"
        description = "May be impersonating official government site."

    # Red flag 4: Targeting SA services
    if any(keyword in url for keyword in ["tender", "capitec", "sassa", "nsfas", "govza-", "gov-za"]):
        red_flags.append("Possible impersonation of SA services")
        score -= 25
        category = "Impersonation"
        description = "Suspicious attempt to mimic South African institutions."

    # Set final safety status
    if score < 50:
        status = "Dangerous"
    elif score < 80:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "score": max(score, 0),
        "status": status,
        "redFlags": red_flags,
        "category": category,
        "description": description,
    }
