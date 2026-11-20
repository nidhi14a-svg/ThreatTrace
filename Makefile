PYTHON ?= python

.PHONY: install frontend backend test docker-up docker-down clean

install:
	cd frontend && npm install
	$(PYTHON) -m pip install -r backend/requirements.txt

frontend:
	cd frontend && npm run dev

backend:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	cd backend && pytest -q
	cd frontend && npm run lint

docker-up:
	docker compose up --build

docker-down:
	docker compose down

clean:
	-rmdir /s /q frontend\.next 2>nul || true
	-rmdir /s /q backend\.pytest_cache 2>nul || true
