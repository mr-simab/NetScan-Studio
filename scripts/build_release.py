import os
import shutil
from pathlib import Path


RELEASE_FOLDER_NAME = "netscan-studio-universal"
INCLUDE_FILES = {"main.py", "README.md", "requirements.txt", "LICENSE"}
INCLUDE_DIRS = {
    "command",
    "core",
    "engines",
    "processing",
    "reports",
    "setup",
    "ui",
    "update",
    "utils",
}
EXCLUDED_NAMES = {
    ".git",
    ".github",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "dist",
    "env",
    "ENV",
    "logs",
    "scripts",
    "tests",
    "venv",
}
EXCLUDED_SUFFIXES = {".log", ".pyc", ".pyo", ".zip"}


def copy_path(source: Path, destination: Path):
    if source.is_dir():
        shutil.copytree(source, destination, ignore=ignore_filter)
    else:
        shutil.copy2(source, destination)


def ignore_filter(_directory: str, names):
    ignored = []
    for name in names:
        if name in EXCLUDED_NAMES:
            ignored.append(name)
            continue

        suffix = Path(name).suffix.lower()
        if suffix in EXCLUDED_SUFFIXES:
            ignored.append(name)

    return ignored


def build_release():
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "dist"
    staging_root = dist_dir / RELEASE_FOLDER_NAME
    zip_base = dist_dir / RELEASE_FOLDER_NAME

    if staging_root.exists():
        shutil.rmtree(staging_root)

    dist_dir.mkdir(exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)

    for name in sorted(INCLUDE_FILES):
        source = repo_root / name
        if source.exists():
            copy_path(source, staging_root / name)

    for name in sorted(INCLUDE_DIRS):
        source = repo_root / name
        if source.exists():
            copy_path(source, staging_root / name)

    archive_path = shutil.make_archive(str(zip_base), "zip", root_dir=dist_dir, base_dir=RELEASE_FOLDER_NAME)

    print(f"Release package ready: {archive_path}")
    print(f"Staging folder: {staging_root}")


if __name__ == "__main__":
    build_release()
