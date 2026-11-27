PYTHON ?= python

.PHONY: install frontend backend test test-security build build-scanner up down docker-up docker-down logs clean-workspaces scanner-versions clean

install:
	cd frontend && npm install
	$(PYTHON) -m pip install -r backend/requirements.txt

frontend:
	cd frontend && npm run dev

backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	cd backend && pytest -v

test-security:
	cd backend && pytest tests/test_zip_security.py tests/test_redaction_verification.py tests/test_end_to_end_security.py tests/test_delete_retention.py tests/test_finding_compatibility.py tests/test_scanner_report_mapping.py -v

build:
	docker compose build

build-scanner:
	docker compose build scanner

up:
	docker compose up -d

down:
	docker compose down

docker-up:
	docker compose up --build

docker-down:
	docker compose down

logs:
	docker compose logs -f

clean-workspaces:
	$(PYTHON) scripts/cleanup_workspaces.py

scanner-versions:
	docker compose run --rm scanner --check-tools

clean:
	-rmdir /s /q frontend\.next 2>nul || true
	-rmdir /s /q backend\.pytest_cache 2>nul || true
