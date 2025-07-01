LinkGuard Backend - Scam and Phishing URL Analyzer

About This Project:
This is the backend API for LinkGuard - a tool that helps protect users by detecting possibly
dangerous or phishing URLs using a trust score system.

Features:
- Accepts a suspicious URL via API.
- Returns a trust score (0 to 100).
- Identifies if the link is safe, caution, or suspicious.
- Flags red signals like domain spoofing or strange patterns.

Technologies Used:
- Python 3
- FastAPI (web API framework)
- Uvicorn (server)
- CORS middleware (for frontend/backend communication)
- Render.com (for live deployment)

How to Run This Backend Locally (Step-by-Step):
1. Download or clone the backend folder to your computer.
2. Open Command Prompt or Terminal and go to the backend folder.
3. Create a virtual environment:
 On Windows:
 venv\Scripts\activate
 On Mac/Linux:
 source venv/bin/activate

4. Install all Python dependencies:
 pip install -r requirements.txt

5. Start the FastAPI server:
 uvicorn main:app --reload
6. Visit in browser: http://localhost:8000/docs

CORS Notice:
This backend uses CORS so your frontend (hosted on Vercel or localhost) can send requests
without any problem.

Example API Call:
POST /analyze
Content-Type: application/json
{
 "url": "http://example.com"
}
Returns:
{
 "score": 45,
 "category": "Phishing",
 "redFlags": ["Domain looks suspicious", "Misspelled name"],
 "status": "suspicious"
}

Live Backend URL (Render):
https://linkguard-backend.onrender.com

linkguard/backend/screenshots/linkguard-backend-preview.png

Author:
MCreated with 💻 by Charles Mosehla Charles Maponya 🇿🇦
For cybersecurity learning, personal growth, and protecting users online.