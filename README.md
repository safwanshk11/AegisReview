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

Copy `.env.example` to `.env` and add a `GITHUB_TOKEN` later if private repository support is needed. This scaffold currently accepts publicly cloneable GitHub repositories.
