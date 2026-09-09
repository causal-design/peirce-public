# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
from typing import Any

import yaml


EVIDENCE = {
    "apt_packages": ("apt-packages.tsv", "Package\tVersion\tArchitecture\nbash\t5.2\tamd64\ngit\t2.4\tamd64\n"),
    "python_packages": ("python-packages.txt", "numpy==2.5.1\npandas==3.0.5\n"),
    "r_packages": ("r-packages.tsv", "Package\tVersion\nbase\t4.6.1\ndata.table\t1.18.0\n"),
    "r_session_info": (
        "r-session-info.txt",
        "R version 4.6.1\nPlatform: x86_64-pc-linux-gnu\nattached base packages:\n[1] stats graphics grDevices utils datasets methods base\nR library: /usr/lib/R\nPython: /opt/cpython/3.14.7\n",
    ),
    "capability_check": (
        "capability-check.txt",
        "\n".join((
            "OK: representative research binaries are present",
            "OK: CPython 3.14.7 is the default research Python",
            "OK: pinned Python scientific/data imports",
            "OK: ancillary Ubuntu Python imports",
            "OK: R 4.6.1 is installed",
            "OK: R package manifest and session info are present",
            "OK: R analysis/document imports",
            "OK: version probes passed without network access",
        )) + "\n",
    ),
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_release(root: Path, release_id: str, image_character: str, recipe_commit: str) -> None:
    release = root / "ops/image/releases" / release_id
    release.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, dict[str, str]] = {}
    for key, (filename, content) in EVIDENCE.items():
        path = release / filename
        path.write_text(content, encoding="utf-8")
        evidence[key] = {"file": filename, "sha256": _digest(path)}

    tracked = {declaration["file"]: declaration["sha256"] for declaration in evidence.values()}
    payload: dict[str, Any] = {
        "schema_version": 1,
        "release_id": release_id,
        "status": "accepted",
        "accepted_at": "2026-08-09",
        "recorded_at": "2026-08-10",
        "reproducibility": "not_guaranteed",
        "identity": {
            "profile_recipe_commit": recipe_commit,
            "image_id": "sha256:" + image_character * 64,
            "base_image_digest": "sha256:" + "c" * 64,
        },
        "build_inputs": {
            "recipe": "ops/image/recipe/Dockerfile",
            "apt_packages": "ops/image/recipe/apt-packages.txt",
            "python_requirements": "ops/image/recipe/python-requirements.txt",
            "capability_check": "ops/image/recipe/check-capabilities.sh",
        },
        "hermes": {"version": "v2026.8.3", "package": "0.20.0", "commit": "a" * 40},
        "operator_attestation": {
            "image_manifest_correspondence": True,
            "source": "external-container-correlation",
        },
        "evidence": evidence,
        "tracked_file_sha256": tracked,
    }
    (release / "release.yaml").write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def make_repo(base: Path, *, release_id: str | None = "2026-08-09-fixture") -> Path:
    root = base / "repo"
    (root / "compatibility").mkdir(parents=True)
    recipe = root / "ops/image/recipe"
    recipe.mkdir(parents=True)
    for filename in ("Dockerfile", "apt-packages.txt", "python-requirements.txt", "check-capabilities.sh"):
        if filename == "Dockerfile":
            content = "ARG BASE_IMAGE=ubuntu:24.04@sha256:" + "c" * 64 + "\n"
        else:
            content = f"fixture {filename}\n"
        (recipe / filename).write_text(content, encoding="utf-8")
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "add", "ops/image/recipe")
    _git(root, "commit", "-m", "recipe fixture")
    recipe_commit = _git(root, "rev-parse", "HEAD")
    (root / "ops/image/releases").mkdir(parents=True)
    (root / "ops/image/releases/README.md").write_text("accepted release documentation\n", encoding="utf-8")
    if release_id is None:
        current: str | None = None
    else:
        current = release_id
        _write_release(root, release_id, "d", recipe_commit)
    (root / "compatibility/hermes.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, "current_release": current}, sort_keys=False),
        encoding="utf-8",
    )
    return root


def add_release(root: Path, release_id: str, image_character: str = "e") -> None:
    _write_release(root, release_id, image_character, _git(root, "rev-parse", "HEAD"))
    (root / "compatibility/hermes.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, "current_release": release_id}, sort_keys=False),
        encoding="utf-8",
    )


def refresh_hashes(root: Path, release_id: str = "2026-08-09-fixture") -> None:
    release = root / "ops/image/releases" / release_id
    data = yaml.safe_load((release / "release.yaml").read_text(encoding="utf-8"))
    for key, (filename, _) in EVIDENCE.items():
        digest = _digest(release / filename)
        data["evidence"][key]["sha256"] = digest
        data["tracked_file_sha256"][filename] = digest
    (release / "release.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
