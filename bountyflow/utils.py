"""Shell / FS / validation helpers."""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .logging_setup import LOG


def q(p: object) -> str:
    """Shell-quote a path/arg (workspace may contain spaces, e.g. 'My Tools')."""
    return shlex.quote(str(p))


def run_cmd(cmd: str, cwd: Path, out_file: Path | None = None, timeout: int = 3600):
    """Run shell cmd. Never raises. Saves combined blob to out_file."""
    LOG.info("$ %s", cmd)
    start = time.time()
    try:
        p = subprocess.run(cmd, shell=True, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        elapsed = round(time.time() - start, 1)
        blob = (
            f"$ {cmd}\n[rc={p.returncode}] [{elapsed}s]\n"
            f"--- stdout ---\n{p.stdout[-20000:]}\n--- stderr ---\n{p.stderr[-5000:]}"
        )
        if out_file:
            out_file.write_text(blob)
        if p.returncode != 0:
            LOG.warning("rc=%s (see %s)", p.returncode, out_file)
        return p.returncode, p
    except subprocess.TimeoutExpired:
        LOG.error("TIMEOUT after %ss: %s", timeout, cmd[:200])
        if out_file:
            out_file.write_text(f"$ {cmd}\n[TIMEOUT {timeout}s]\n")
        return 124, None


def parse_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]


def atomic_write(p: Path, text: str) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(p)


def save_step(rdir: Path, name: str, cmd: str, rc: object, extra: dict | None = None) -> dict:
    data = {"step": name, "cmd": cmd, "rc": rc, "time": datetime.now(timezone.utc).isoformat(), **(extra or {})}
    atomic_write(rdir / f"STEP_{name}.json", json.dumps(data, indent=2))
    return data


def validate_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,248}[a-z0-9])?", d):
        raise ValueError(f"invalid domain: {d!r}")
    return d


def validate_url(u: str) -> str:
    p = urlparse(u.strip())
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"invalid URL (need http(s)://host): {u!r}")
    return u.rstrip("/")


def parse_phases(s: str) -> set[int]:
    s = s.strip().lower()
    if s == "all":
        return {1, 2, 3}
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if part not in ("1", "2", "3"):
            raise ValueError(f"--phases must be 1,2,3 or all (got {s!r})")
        out.add(int(part))
    return out
