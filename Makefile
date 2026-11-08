.PHONY: setup backend frontend build run-phishing run-landscape run-all serve dev test clean-data

PY=backend/.venv/bin/python

setup: backend frontend          ## install everything from a clean checkout

backend:
	cd backend && uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"

frontend:
	cd frontend && npm install

build:                           ## production frontend bundle, served by the API on :8000
	cd frontend && npm run build

run-phishing:                    ## P4 pipeline, blocking, logs to stdout
	cd backend && .venv/bin/python -m app.cli run phishing

run-landscape:                   ## P6 pipeline
	cd backend && .venv/bin/python -m app.cli run landscape

run-all: run-landscape run-phishing

serve:                           ## API + built frontend on http://127.0.0.1:8000
	cd backend && .venv/bin/python -m app.cli serve --port 8000

dev:                             ## API on :8000 with reload + Vite dev server on :5173
	(cd backend && .venv/bin/python -m app.cli serve --port 8000 --reload &) ; cd frontend && npm run dev

test:
	cd backend && .venv/bin/python -m pytest -q
	cd frontend && npx tsc -b

clean-data:                      ## wipe database, caches and artifacts (clean start)
	rm -rf data/ctiops.db data/ctiops.db-wal data/ctiops.db-shm data/cache data/artifacts
