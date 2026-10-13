"""Source manifests: which upstream rule repositories Chain pulls from, pinned to a commit.

    sources/sigmahq.yaml
    ---
    name: sigmahq
    url: https://github.com/SigmaHQ/sigma
    ref: 8a48134...            # pinned commit; `chain sources sync --update` moves it
    branch: master
    format: sigma
    paths: [rules, rules-threat-hunting, rules-emerging-threats]
    license: DRL-1.1
    attribution: SigmaHQ and contributors

A local directory works as a source too (`url: /path/to/rules`), with no pin.
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

FORMATS = {"auto", "sigma", "yara", "suricata", "chain"}
DEFAULT_SOURCES_DIR = Path("sources")
DEFAULT_CACHE_DIR = Path(".chain-cache/sources")
DEFAULT_CORPUS_DIR = Path("corpus")


class Source(BaseModel):
    name: str
    url: str
    ref: str = ""                      # pinned commit; empty for a local directory
    branch: str = "main"               # where `update` looks for the newest commit
    format: str = "auto"
    paths: list[str] = Field(default_factory=lambda: ["."])
    exclude: list[str] = Field(default_factory=list)   # glob patterns, relative to the repo root
    skip_status: list[str] = Field(default_factory=lambda: ["deprecated", "unsupported"])
    license: str = ""
    license_url: str = ""
    attribution: str = ""
    schedule: str = "weekly"           # informational: how often to run sync
    variables: dict[str, str] = Field(default_factory=dict)   # Suricata $HOME_NET etc.; Sigma placeholders
    description: str = ""
    added: str = ""
    last_sync: str | None = None
    last_sync_ref: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", v):
            raise ValueError("source name must be lowercase letters, digits, '.', '_' or '-'")
        return v

    @field_validator("format")
    @classmethod
    def _format(cls, v: str) -> str:
        if v not in FORMATS:
            raise ValueError(f"format must be one of {sorted(FORMATS)}")
        return v

    @property
    def is_local(self) -> bool:
        return is_local(self.url)

    def manifest_path(self, sources_dir: Path = DEFAULT_SOURCES_DIR) -> Path:
        return Path(sources_dir) / f"{self.name}.yaml"


def is_local(url: str) -> bool:
    return url.startswith(("/", "./", "../", "file://")) or Path(url).exists()


def _local_path(url: str) -> Path:
    return Path(url[len("file://"):] if url.startswith("file://") else url).resolve()


def name_from_url(url: str) -> str:
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    tail = re.sub(r"\.git$", "", tail).lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", tail).strip("-") or "source"


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ------------------------------------------------------------------ manifests
def load_source(name_or_path: str | Path, sources_dir: Path = DEFAULT_SOURCES_DIR) -> Source:
    p = Path(name_or_path)
    if not p.exists():
        p = Path(sources_dir) / f"{name_or_path}.yaml"
    if not p.exists():
        raise FileNotFoundError(f"no source manifest {name_or_path!r} in {sources_dir}")
    data = yaml.safe_load(p.read_text()) or {}
    return Source(**data)


def list_sources(sources_dir: Path = DEFAULT_SOURCES_DIR) -> list[Source]:
    d = Path(sources_dir)
    if not d.exists():
        return []
    return [load_source(p, d) for p in sorted(d.glob("*.yaml"))]


def save_source(src: Source, sources_dir: Path = DEFAULT_SOURCES_DIR) -> Path:
    d = Path(sources_dir)
    d.mkdir(parents=True, exist_ok=True)
    data = src.model_dump(exclude_none=True)
    p = src.manifest_path(d)
    p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return p


def add_source(url: str, name: str | None = None, sources_dir: Path = DEFAULT_SOURCES_DIR,
               **fields: Any) -> Source:
    """Create a manifest. Git sources are pinned to the branch head at the time of adding."""
    src = Source(name=name or name_from_url(url), url=url, added=now(), **fields)
    if src.manifest_path(sources_dir).exists():
        raise FileExistsError(f"source {src.name!r} already exists")
    if not src.ref and (not src.is_local or (_local_path(src.url) / ".git").exists()):
        src.ref = resolve_head(src.url, src.branch)
    save_source(src, sources_dir)
    return src


# ------------------------------------------------------------------ git
def _git(*args: str, cwd: Path | None = None) -> str:
    cmd = ["git", "-c", "uploadpack.allowAnySHA1InWant=true", "-c", "uploadpack.allowReachableSHA1InWant=true", *args]
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout


def _git_url(url: str) -> str:
    if is_local(url) and not url.startswith("file://"):
        return _local_path(url).as_uri()
    return url


def resolve_head(url: str, branch: str) -> str:
    """Commit hash a branch points at upstream. Tries `branch`, then main / master."""
    candidates = [branch] + [b for b in ("main", "master") if b != branch]
    out = _git("ls-remote", _git_url(url), *[f"refs/heads/{b}" for b in candidates])
    found = {line.split("\t")[1].rsplit("/", 1)[-1]: line.split("\t")[0] for line in out.splitlines() if "\t" in line}
    for b in candidates:
        if b in found:
            return found[b]
    raise RuntimeError(f"no branch {branch!r} (or main/master) at {url}")


def fetch(src: Source, cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    """Return a directory holding the source at its pinned commit."""
    if src.is_local:
        p = _local_path(src.url)
        if (p / ".git").exists() and src.ref:
            return _checkout(src, cache_dir)
        if not p.is_dir():
            raise FileNotFoundError(f"local source {src.url} is not a directory")
        return p
    if not src.ref:
        raise RuntimeError(f"source {src.name} has no pinned ref; run `chain sources sync --update {src.name}`")
    return _checkout(src, cache_dir)


def _checkout(src: Source, cache_dir: Path) -> Path:
    d = (Path(cache_dir) / src.name).resolve()
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".git").exists():
        _git("init", "-q", cwd=d)
        _git("remote", "add", "origin", _git_url(src.url), cwd=d)
    else:
        _git("remote", "set-url", "origin", _git_url(src.url), cwd=d)
    head = ""
    try:
        head = _git("rev-parse", "HEAD", cwd=d).strip()
    except RuntimeError:
        pass
    if head != src.ref:
        _git("fetch", "-q", "--depth", "1", "origin", src.ref, cwd=d)
        _git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=d)
    return d
