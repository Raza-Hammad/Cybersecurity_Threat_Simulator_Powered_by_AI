# FYP Project Developer Guidelines

This file outlines build, run, and quality commands, along with coding styles for this project.

## Development Commands

### Backend (FastAPI)
- **Activate Virtual Environment**:
  - Windows: `.\backend\venv\Scripts\Activate.ps1`
  - macOS/Linux: `source backend/venv/bin/activate`
- **Install Dependencies**: `pip install -r backend/requirements.txt`
- **Run Dev Server**: `uvicorn backend.app.main:app --reload --port 8000`
- **Check Health**: `curl http://127.0.0.1:8000/api/health`
- **Run API Integration & Auth Test**: `python -m app.ml.generate_test_alerts` (from `backend/` directory)
- **Run WebSocket Telemetry Test**: `python -m app.ml.test_websocket` (from `backend/` directory)
- **Run Simulator Telemetry Test**: `python -m app.ml.test_simulator` (from `backend/` directory)

### Frontend (React + Vite)
- **Install Dependencies**: `npm install` (inside `/frontend`)
- **Run Dev Server**: `npm run dev` (inside `/frontend`)
- **Build Production Bundle**: `npm run build` (inside `/frontend`)

## Coding & Style Guidelines

### Python (Backend)
- Use strict PEP8 standards.
- Use explicit type hints for function arguments and return values.
- Document modules, classes, and complex functions with Google-style docstrings.
- Structure endpoints clearly inside FastAPI routers.
- Handle database operations safely with SQLModel sessions.

### TypeScript / React (Frontend)
- Use functional React components with hooks.
- Use TypeScript type annotations strictly; avoid `any`.
- Keep layouts clean, interactive, and responsive (Mobile-first grid/flex).
- Put reusable components in `frontend/src/components`.
- Manage CSS styling through Tailwind CSS.
