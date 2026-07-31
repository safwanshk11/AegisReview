# Deploying AegisReview to Vercel

AegisReview deploys as **two separate Vercel projects from this one repo** — a Python
API (`backend/`) and a Vite static site (`frontend/`). Import the repo twice and set a
different **Root Directory** for each.

## 1. Backend project (the API)

- **Import** this repo in Vercel → set **Root Directory** to `backend`.
- **Framework Preset:** Other. Vercel builds the function from `backend/api/index.py`
  (the FastAPI ASGI app) using `backend/vercel.json`, which routes every path to it.
- **Environment Variables:**

  | Name | Required | Notes |
  | --- | --- | --- |
  | `GEMINI_API_KEY` | for AI review | Google Gemini key. Without it, scans still run (review steps are skipped). |
  | `ALLOWED_ORIGINS` | yes | The frontend's URL, e.g. `https://aegis-frontend.vercel.app` (comma-separate multiple). Controls CORS. |
  | `AEGIS_LLM_MODEL` | no | Defaults to `gemini-flash-latest`. |
  | `AEGIS_REVIEW_LIMIT` | no | Max findings reviewed per scan (default `6`). |
  | `GITHUB_TOKEN` | no | Raises GitHub archive-download rate limits (60/hr → 5000/hr). |

- Deploy, then note the URL, e.g. `https://aegis-backend.vercel.app`.

## 2. Frontend project (the dashboard)

- **Import the same repo again** as a second project → set **Root Directory** to `frontend`.
- **Framework Preset:** Vite (auto-detected).
- **Environment Variable:**

  | Name | Required | Notes |
  | --- | --- | --- |
  | `VITE_API_URL` | yes | The backend URL, e.g. `https://aegis-backend.vercel.app` (no trailing slash). Baked in at build time. |

- Deploy, then note the URL, e.g. `https://aegis-frontend.vercel.app`.

## 3. Wire the two together

There's a chicken-and-egg between the two URLs, so:

1. Deploy the **backend** first → copy its URL.
2. Set the frontend's `VITE_API_URL` to that URL → deploy the **frontend** → copy its URL.
3. Set the backend's `ALLOWED_ORIGINS` to the frontend URL → **redeploy the backend**.

Changing `VITE_API_URL` requires a frontend redeploy (it's compiled in). Changing
`ALLOWED_ORIGINS`/`GEMINI_API_KEY` requires a backend redeploy.

## Caveats on serverless

- **Function timeout:** `backend/vercel.json` sets `maxDuration: 60` (the Hobby-plan max).
  Static scans finish comfortably; AI review over a large repo can exceed 60s and cut the
  live stream short. On the Pro plan, raise `maxDuration` (up to 300) in `backend/vercel.json`,
  and/or keep AI review off or `AEGIS_REVIEW_LIMIT` low.
- **GitHub rate limits:** anonymous archive downloads are limited; set `GITHUB_TOKEN` for headroom.
- Secrets live in the Vercel dashboard — the `.env` files are gitignored and are **not** deployed.

## Local development (unchanged)

```bash
# Backend  (reads the repo-root .env)
cd backend && .venv/bin/uvicorn app.main:app --port 8001

# Frontend (reads frontend/.env)
cd frontend && npm run dev
```
