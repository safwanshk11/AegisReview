from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.agent import AgenticReviewer
from app.scanner import Finding, scan_repository

# Load the repository-root .env (matches .env.example) so GEMINI_API_KEY and
# other backend settings are available without exporting them by hand.
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_PATH)

MAX_FILES = 500
MAX_ARCHIVE_BYTES = 100_000_000
IGNORED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "dist", "build"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class RepositoryReference:
    owner: str
    name: str

    @property
    def archive_url(self) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.name}/zipball"


class RepositoryDownloadError(RuntimeError):
    """Raised when a GitHub repository archive cannot be downloaded safely."""


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


def validate_github_url(url: str) -> RepositoryReference:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise HTTPException(400, "Enter a GitHub repository URL, such as https://github.com/owner/repository.")

    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) < 2:
        raise HTTPException(400, "The GitHub URL must include an owner and repository name.")

    return RepositoryReference(owner=segments[0], name=segments[1].removesuffix(".git"))


def download_repository_archive(repository: RepositoryReference, destination: Path) -> None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "AegisReview"}
    if github_token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {github_token}"

    archive_path: Path | None = None
    try:
        request = Request(repository.archive_url, headers=headers)
        with urlopen(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_ARCHIVE_BYTES:
                raise RepositoryDownloadError("The repository archive is too large to scan.")
            with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".zip", delete=False) as archive_file:
                archive_path = Path(archive_file.name)
                downloaded = 0
                while chunk := response.read(64 * 1024):
                    downloaded += len(chunk)
                    if downloaded > MAX_ARCHIVE_BYTES:
                        raise RepositoryDownloadError("The repository archive is too large to scan.")
                    archive_file.write(chunk)

        with ZipFile(archive_path) as archive:
            members = archive.infolist()
            roots: set[str] = set()
            for member in members:
                member_path = PurePosixPath(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RepositoryDownloadError("The repository archive contains an unsafe path.")
                if member_path.parts:
                    roots.add(member_path.parts[0])
            if len(roots) != 1:
                raise RepositoryDownloadError("The repository archive has an unexpected structure.")
            archive.extractall(destination.parent)

        source = destination.parent / roots.pop()
        if not source.is_dir():
            raise RepositoryDownloadError("The repository archive did not contain source files.")
        source.rename(destination)
    except (HTTPError, URLError, OSError, BadZipFile) as error:
        raise RepositoryDownloadError("AegisReview could not download that repository. Check that it exists and is public.") from error
    finally:
        if archive_path:
            archive_path.unlink(missing_ok=True)


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
    allow_origin_regex=os.getenv("ALLOWED_ORIGIN_REGEX") or None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AegisReview API"}


@app.post("/api/repositories/inspect", response_model=RepositoryInspection)
def inspect_repository(request: RepositoryRequest) -> RepositoryInspection:
    repository = validate_github_url(request.url)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
            repo_path = Path(temporary_directory) / "repository"
            download_repository_archive(repository, repo_path)
            files, truncated = walk_repository(repo_path)
    except RepositoryDownloadError as error:
        raise HTTPException(422, str(error)) from error

    return RepositoryInspection(repository_url=request.url.strip(), files=files, file_count=len(files), truncated=truncated)


@app.post("/api/repositories/scan", response_model=RepositoryScan)
def scan_repository_for_vulnerabilities(request: RepositoryRequest) -> RepositoryScan:
    repository = validate_github_url(request.url)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
            repo_path = Path(temporary_directory) / "repository"
            download_repository_archive(repository, repo_path)
            findings, scanned_files = scan_repository(repo_path)
            findings, agent_activity = AgenticReviewer().review_findings(repo_path, findings)
    except RepositoryDownloadError as error:
        raise HTTPException(422, str(error)) from error

    return RepositoryScan(
        repository_url=request.url.strip(),
        scanned_files=scanned_files,
        findings=findings,
        agent_activity=agent_activity,
    )


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def download_with_progress(repository: RepositoryReference, repo_path: Path) -> Iterator[str]:
    yield sse_event("status", {"phase": "cloning", "percent": 0})
    download_repository_archive(repository, repo_path)
    yield sse_event("status", {"phase": "cloning", "percent": 100})


@app.post("/api/repositories/scan/stream")
def stream_repository_scan(request: RepositoryRequest) -> StreamingResponse:
    repository = validate_github_url(request.url)

    def events() -> Iterator[str]:
        try:
            with tempfile.TemporaryDirectory(prefix="aegis-review-") as temporary_directory:
                repo_path = Path(temporary_directory) / "repository"
                yield from download_with_progress(repository, repo_path)
                yield sse_event("status", {"phase": "scanning"})
                findings, scanned_files = scan_repository(repo_path)
                yield sse_event("findings", {
                    "repository_url": request.url.strip(),
                    "scanned_files": scanned_files,
                    "findings": [VulnerabilityFinding(**finding).model_dump() for finding in findings],
                })
                if request.review:
                    load_dotenv(ENV_PATH, override=True)  # pick up a freshly-changed key without restarting
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
        except RepositoryDownloadError as error:
            yield sse_event("error", {"detail": str(error)})
        except Exception as error:
            yield sse_event("error", {"detail": f"The scan stopped unexpectedly: {str(error)[:200]}"})

    return StreamingResponse(events(), media_type="text/event-stream")
