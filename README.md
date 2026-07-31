# AegisReview

A small full-stack starting point for inspecting the file tree of a public GitHub repository.

## Run locally

Start the API:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Start the web app in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The frontend calls `GET /api/health` on load and sends repository URLs to `POST /api/repositories/inspect`.

## Vulnerability scanning

`POST /api/repositories/scan` accepts the same JSON body as inspection:

```json
{ "url": "https://github.com/owner/repository" }
```

It returns `scanned_files` and structured findings containing `file`, `line_number`, `rule`, and `severity`. The built-in, offline checks cover high-entropy hardcoded secrets, SQL string interpolation, XSS-prone template APIs, `eval`/`exec`, and a small known-bad dependency list for `package.json` and `requirements.txt`.

Copy `.env.example` to `.env` and add a `GEMINI_API_KEY` from [Google AI Studio](https://aistudio.google.com/app/apikey) to enable the optional agentic plan → act → review loop. It defaults to `gemini-flash-latest`, and `AEGIS_REVIEW_LIMIT=6` caps the number of findings sent to Gemini for one scan. Add a `GITHUB_TOKEN` later if private repository support is needed. This scaffold currently accepts publicly cloneable GitHub repositories.

## Deploy to Vercel

Deploy the backend and frontend as **two separate Vercel projects** from this repository. Import the repository twice in Vercel and select the relevant Root Directory each time.

### Backend API

1. Create a Vercel project with `backend` as its Root Directory.
2. Vercel automatically detects `backend/index.py`, which exports the FastAPI app.
3. Set the following Production and Preview environment variables:

```text
GEMINI_API_KEY=your_google_ai_studio_key
AEGIS_LLM_MODEL=gemini-flash-latest
AEGIS_REVIEW_LIMIT=6
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

After deployment, confirm `https://your-backend.vercel.app/api/health` returns an `ok` status. Keep `GEMINI_API_KEY` in the backend project only; it must never be exposed as a `VITE_` variable.

### Frontend web app

1. Create another Vercel project with `frontend` as its Root Directory.
2. `frontend/vercel.json` builds the Vite app with `npm run build` and serves the `dist` directory.
3. Set the following Production and Preview environment variable before deploying:

```text
VITE_API_URL=https://your-backend.vercel.app
```

Redeploy the frontend after changing `VITE_API_URL`, because Vite embeds `VITE_` variables during its build. Add the frontend deployment URL to the backend `ALLOWED_ORIGINS` value and redeploy the backend so browser requests are permitted.
