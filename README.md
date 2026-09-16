# MailSentinel

Email threat intelligence workspace with a FastAPI backend and React/Vite dashboard.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.app:app --reload
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Copy `.env.example` to `.env` and configure provider keys when needed. The frontend can use `VITE_API_BASE_URL` (default `http://localhost:8000`).

## API examples

```powershell
curl -F "file=@sample.eml" http://localhost:8000/api/analyses
curl http://localhost:8000/api/analyses/{analysis_id}
curl -OJ http://localhost:8000/api/analyses/{analysis_id}/report
```

## Local MVP limitations

Jobs use one daemon thread and a JSON-backed persistence file for a dependency-light local MVP. Restart recovery is intentionally explicit: records interrupted while processing remain visible and should be retried by a future job-runner enhancement. External lookups are bounded by the upload workflow and are reported as UNKNOWN or UNAVAILABLE when not configured. Email HTML is parsed for links but never rendered, URLs are never visited, and attachment contents are never uploaded.
