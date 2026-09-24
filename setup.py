"""Build the pip package and vendor the Node sources it launches."""

from pathlib import Path
import shutil

from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / "python" / "conduit_debugger" / "_payload"
COPY_NAMES = ("package.json", "package-lock.json", "tsconfig.json", "src", "plugin")


def vendor_payload() -> None:
    if not (ROOT / "package.json").is_file():
        if (PAYLOAD / "package.json").is_file():
            return
        raise SystemExit("package.json is missing from the package sources")
    if PAYLOAD.exists():
        shutil.rmtree(PAYLOAD)
    PAYLOAD.mkdir(parents=True)
    for name in COPY_NAMES:
        source = ROOT / name
        target = PAYLOAD / name
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, target)


vendor_payload()

setup(
    name="conduit-debugger",
    version="0.1.0",
    description="MCP debugger for radare2, x64dbg, cdb, and Frida.",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Alyhnte",
    license="MIT",
    url="https://github.com/Alyhnte/conduit",
    python_requires=">=3.10",
    packages=find_packages("python"),
    package_dir={"": "python"},
    package_data={"conduit_debugger": ["_payload/**/*"]},
    include_package_data=True,
    entry_points={"console_scripts": ["conduit=conduit_debugger.launch:main"]},
)
