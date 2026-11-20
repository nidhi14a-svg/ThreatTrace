# Thread Trace

Thread Trace is a modular, AI-assisted source-code vulnerability detection platform.

## Technology Stack

- Frontend: Next.js App Router, JavaScript, Tailwind CSS
- Backend: Python, FastAPI, Pydantic, Motor
- Database: MongoDB
- Development: Docker Compose, pytest, npm
- Planned scanning: Semgrep, Bandit, Gitleaks/detect-secrets, OSV-Scanner, custom rules

## Repository Structure

- `frontend/` — Next.js application
- `backend/` — FastAPI application and modular scanner interfaces
- `docs/` — development and interface documentation placeholders
- `healthcare_reference/` — reserved reference directory
- `scripts/` — repository automation
- `specs/` — implementation specifications
- `tests/` — integration and end-to-end tests

## Prerequisites

- Node.js 22+
- npm
- Python 3.12+
- Docker and Docker Compose

## Setup

Copy `.env.example` to `.env`, then configure local values. Never commit real API keys or credentials.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Docker

```powershell
docker compose up --build
```

Frontend: `http://localhost:3000`  
Backend: `http://localhost:8000`  
API documentation: `http://localhost:8000/docs`

## Testing

```powershell
cd backend
pytest -q

cd ../frontend
npm run lint
```

## Security Foundation

Uploads must be validated and extracted inside isolated, bounded workspaces. Uploaded source code is never executed. Scanner containers must remain unprivileged and use resource limits. Only sanitized finding context should be sent to an AI provider.
