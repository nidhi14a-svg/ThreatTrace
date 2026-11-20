# Thread Trace Backend

FastAPI foundation for scan orchestration and normalized findings.

## Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Test

```powershell
pytest -q
```
