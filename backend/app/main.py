from __future__ import annotations

import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from git import GitCommandError, Repo
from pydantic import BaseModel, Field

from app.scanner import Finding, scan_repository

MAX_FILES = 500
IGNORED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "dist", "build"}


class RepositoryRequest(BaseModel):
    url: str = Field(..., examples=["https://github.com/owner/repository"])


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


class RepositoryScan(BaseModel):
    repository_url: str
    scanned_files: int
    findings: list[VulnerabilityFinding]


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
    except GitCommandError as error:
        raise HTTPException(422, "AegisReview could not clone that repository. Check that it exists and is public.") from error

    return RepositoryScan(repository_url=request.url.strip(), scanned_files=scanned_files, findings=findings)
