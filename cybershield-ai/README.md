# CyberShield powered by AI: Intelligent Cyber Threat Detection and Digital Safety Platform

## Run
    python -m venv venv && venv\Scripts\activate      (Linux/macOS: source venv/bin/activate)
    pip install -r requirements.txt
    uvicorn main:app --reload
Open http://127.0.0.1:8000 (API docs at /docs).

## Modules (as per synopsis)
| Module | Where |
|---|---|
| User authentication | main.py `/api/register`, `/api/login` (PBKDF2 hashed passwords) |
| URL / SMS / QR analysis | analyzers.py (rules + TF-IDF & Logistic Regression) |
| Report (risk score, category, confidence, advice) | result card in index.html |
| Community reported list (report button, raises risk of reported numbers / links) | main.py `Report` table, `/api/flag/{id}` |
| Scan progress bar with live steps for every check | index.html `runScan()` |
| History and dashboard | `/api/history`, `/api/stats`, Chart.js |
| Database | SQLAlchemy; SQLite default, MySQL via `DATABASE_URL` |

## Notes
- The ML model trains at startup on a small demo set. For real accuracy, train on a larger dataset (e.g. UCI SMS Spam, PhishTank) and save it with joblib.
- Planned later: Android app, browser extension, cloud deployment.
