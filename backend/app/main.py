from __future__ import annotations

import json
import os
import queue
import tempfile
import threading
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse
from git import GitCommandError, RemoteProgress, Repo
from pydantic import BaseModel, Field

from app.agent import AgenticReviewer
from app.scanner import Finding, scan_repository

# Load the repository-root .env (matches .env.example) so GEMINI_API_KEY and
# other backend settings are available without exporting them by hand.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

MAX_FILES = 500
IGNORED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "dist", "build"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class RepositoryRequest(BaseModel):
    url: str = Field(..., examples=["https://github.com/owner/repository"])
    review: bool = False


class RepositoryInspection(BaseModel):
    repository_url: str
    files: list[str]
    file_count: int
    truncated: bool


class VulnerabilityFinding(BaseModel):
    file: str
    line_number: int
    rule: str
    severity: str
    analysis: "FindingAnalysis | None" = None


class FindingAnalysis(BaseModel):
    explanation: str
    diff: str
    review: str
    approved: bool


class AgentActivity(BaseModel):
    finding_id: str
    step: str
    status: str
    detail: str


class RepositoryScan(BaseModel):
    repository_url: str
    scanned_files: int
    findings: list[VulnerabilityFinding]
    agent_activity: list[AgentActivity]


def validate_github_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise HTTPException(400, "Enter a GitHub repository URL, such as https://github.com/owner/repository.")

    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 2:
        raise HTTPException(400, "The GitHub URL must include an owner and repository name.")

    return f"https://github.com/{segments[0]}/{segments[1].removesuffix('.git')}.git"


def walk_repository(root: Path) -> tuple[list[str], bool]:
    files: list[str] = []
    for current_path, directories, filenames in os.walk(root):
        directories[:] = sorted(name for name in directories if name not in IGNORED_DIRECTORIES)
        for filename in sorted(filenames):
            path = Path(current_path, filename)
            files.append(str(path.relative_to(root)))
            if len(files) >= MAX_FILES:
                return files, True
    return files, False


app = FastAPI(title="AegisReview API", version="0.1.0")

allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in allowed_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AegisReview API"}


@app.post("/api/repositories/inspect", response_model=RepositoryInspection)
def inspect_repository(request: RepositoryRequest) -> RepositoryInspection:
    clone_url = validate_github_url(request.url)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
            repo_path = Path(temporary_directory) / "repository"
            Repo.clone_from(clone_url, repo_path, depth=1, multi_options=["--no-tags"])
            files, truncated = walk_repository(repo_path)
    except GitCommandError as error:
        raise HTTPException(422, "AegisReview could not clone that repository. Check that it exists and is public.") from error

    return RepositoryInspection(repository_url=request.url.strip(), files=files, file_count=len(files), truncated=truncated)


@app.post("/api/repositories/scan", response_model=RepositoryScan)
def scan_repository_for_vulnerabilities(request: RepositoryRequest) -> RepositoryScan:
    clone_url = validate_github_url(request.url)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
            repo_path = Path(temporary_directory) / "repository"
            Repo.clone_from(clone_url, repo_path, depth=1, multi_options=["--no-tags"])
            findings, scanned_files = scan_repository(repo_path)
            findings, agent_activity = AgenticReviewer().review_findings(repo_path, findings)
    except GitCommandError as error:
        raise HTTPException(422, "AegisReview could not clone that repository. Check that it exists and is public.") from error

    return RepositoryScan(
        repository_url=request.url.strip(),
        scanned_files=scanned_files,
        findings=findings,
        agent_activity=agent_activity,
    )


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


class CloneProgress(RemoteProgress):
    def __init__(self, updates: queue.Queue) -> None:
        super().__init__()
        self.updates = updates

    def update(self, op_code, cur_count, max_count=None, message="") -> None:
        self.updates.put((op_code, cur_count, max_count))


def clone_with_progress(clone_url: str, repo_path: Path) -> Iterator[str]:
    """Clone in a worker thread while yielding cloning-percent status events."""
    updates: queue.Queue = queue.Queue()
    result: dict[str, GitCommandError] = {}

    def worker() -> None:
        try:
            Repo.clone_from(clone_url, repo_path, depth=1, multi_options=["--no-tags"], progress=CloneProgress(updates))
        except GitCommandError as error:
            result["error"] = error
        finally:
            updates.put(None)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    yield sse_event("status", {"phase": "cloning", "percent": 0})
    last_percent = 0
    while True:
        item = updates.get()
        if item is None:
            break
        op_code, cur_count, max_count = item
        if op_code & RemoteProgress.RECEIVING and max_count:
            percent = min(100, int(cur_count / max_count * 100))
            if percent != last_percent:
                last_percent = percent
                yield sse_event("status", {"phase": "cloning", "percent": percent})
    thread.join()
    if "error" in result:
        raise result["error"]


@app.post("/api/repositories/scan/stream")
def stream_repository_scan(request: RepositoryRequest) -> StreamingResponse:
    clone_url = validate_github_url(request.url)

    def events() -> Iterator[str]:
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
                repo_path = Path(temporary_directory) / "repository"
                yield from clone_with_progress(clone_url, repo_path)
                yield sse_event("status", {"phase": "scanning"})
                findings, scanned_files = scan_repository(repo_path)
                yield sse_event("findings", {
                    "repository_url": request.url.strip(),
                    "scanned_files": scanned_files,
                    "findings": [VulnerabilityFinding(**finding).model_dump() for finding in findings],
                })
                if request.review:
                    limit = int(os.getenv("AEGIS_REVIEW_LIMIT", "6"))
                    order = sorted(range(len(findings)), key=lambda index: SEVERITY_RANK.get(findings[index]["severity"], 0), reverse=True)[:limit]
                    reviewed = 0
                    for event in AgenticReviewer().iter_review(repo_path, [findings[index] for index in order]):
                        if event["type"] == "activity":
                            yield sse_event("activity", event["activity"])
                        else:
                            analysis = event["finding"].get("analysis")
                            if analysis:
                                yield sse_event("analysis", {"index": order[reviewed], "analysis": analysis})
                            reviewed += 1
                yield sse_event("done", {})
        except GitCommandError:
            yield sse_event("error", {"detail": "AegisReview could not clone that repository. Check that it exists and is public."})
        except Exception as error:
            yield sse_event("error", {"detail": f"The scan stopped unexpectedly: {str(error)[:200]}"})

    return StreamingResponse(events(), media_type="text/event-stream")
