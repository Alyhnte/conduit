"""Install Node dependencies once, then run the Conduit MCP server."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

VERSION_FILE = ".conduit-debugger-version"
COPY_NAMES = ("package.json", "package-lock.json", "tsconfig.json", "src", "plugin")


def main() -> None:
    node = shutil.which("node")
    npm = shutil.which("npm")
    if node is None or npm is None:
        sys.stderr.write("conduit needs Node.js 20+ and npm on PATH.\n")
        sys.exit(1)
    app = ensure_app()
    completed = subprocess.run([node, str(app / "dist" / "server.js"), *sys.argv[1:]])
    sys.exit(completed.returncode)


def ensure_app() -> Path:
    payload = bundled_payload()
    version = (payload / "package.json").read_text(encoding="utf-8")
    cache = Path.home() / ".conduit-debugger" / "app"
    stamp = cache / VERSION_FILE
    ready = (cache / "dist" / "server.js").is_file() and stamp.is_file() and stamp.read_text(encoding="utf-8") == version
    if not ready:
        if cache.exists():
            shutil.rmtree(cache)
        cache.mkdir(parents=True)
        for name in COPY_NAMES:
            source = payload / name
            target = cache / name
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        npm = shutil.which("npm")
        if npm is None:
            sys.stderr.write("npm disappeared from PATH.\n")
            sys.exit(1)
        subprocess.run([npm, "ci"], cwd=cache, check=True)
        stamp.write_text(version, encoding="utf-8")
    return cache


def bundled_payload() -> Path:
    here = Path(__file__).resolve().parent
    bundled = here / "_payload"
    if (bundled / "package.json").is_file():
        return bundled
    repo = here.parents[1]
    if (repo / "package.json").is_file() and (repo / "src").is_dir():
        return repo
    sys.stderr.write("Conduit payload is missing from the installed package.\n")
    sys.exit(1)
