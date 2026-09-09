#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate the portable, accepted research-image release contract."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import date
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI setup
    raise SystemExit("PyYAML is required; install ops/image/verify/requirements.txt") from exc


HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT40 = re.compile(r"^[0-9a-f]{40}$")
RELEASE_ID = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9][a-z0-9-]*$")
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]*$")
PYTHON_PACKAGE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.+-]*)==([^\s]+)$")
R_VERSION = re.compile(r"^R version [0-9]+\.[0-9]+\.[0-9]+", re.MULTILINE)
HERMES_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
NUMERIC_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")

TOP_KEYS = {
    "schema_version", "release_id", "status", "accepted_at", "recorded_at",
    "reproducibility", "identity", "build_inputs", "hermes",
    "operator_attestation", "evidence", "tracked_file_sha256",
}
IDENTITY_KEYS = {"profile_recipe_commit", "image_id", "base_image_digest"}
BUILD_INPUT_KEYS = {"recipe", "apt_packages", "python_requirements", "capability_check"}
HERMES_KEYS = {"version", "package", "commit"}
ATTESTATION_KEYS = {"image_manifest_correspondence", "source"}
EVIDENCE_KEYS = {
    "apt_packages": "apt-packages.tsv",
    "python_packages": "python-packages.txt",
    "r_packages": "r-packages.tsv",
    "r_session_info": "r-session-info.txt",
    "capability_check": "capability-check.txt",
}

YAML_TAGS = {
    "tag:yaml.org,2002:map",
    "tag:yaml.org,2002:seq",
    "tag:yaml.org,2002:str",
    "tag:yaml.org,2002:null",
    "tag:yaml.org,2002:bool",
    "tag:yaml.org,2002:int",
    "tag:yaml.org,2002:float",
}
KNOWN_HOST_ROOTS = (
    "/home/", "/root/", "/Users/", "/var/folders/", "/srv/hermes/", "/etc/hermes/",
)
SECRET_MARKERS = (
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]+"),
    re.compile(r"(?i)\b(?:xox[baprs]-|sk-[a-z0-9])"),
    re.compile(r"(?i)\b(?:eyJ[A-Za-z0-9_-]*)\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?i)\b(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:authorization|bearer|cookie|session[-_ ]?token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+\S+"),
    re.compile(
        r'''(?i)["']?(?:aws_access_key_id|aws_secret_access_key|aws_session_token|authorization|cookie|session[-_ ]?token)["']?\s*[:=]\s*["']?\S+'''
    ),
    re.compile(r"(?i)\b(?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|session[-_ ]?cookie|password)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(?:private[-_ ]?key|credential|token|session[-_ ]?cookie)[-_ ]?(?:path|file)?\s*[:=]\s*/"),
)
RAW_EVIDENCE_MARKERS = (
    re.compile(r"(?i)\braw\s+(?:slack|container|operator)\b"),
    re.compile(r"(?i)\b(?:slack[_ -]nonce|container[_ -]id|operator[_ -]log)\b"),
    re.compile(r"(?i)\b(?:mainpid|invocationid|backup[_ -]path)\b"),
)
CANONICAL_BUILD_INPUTS = {
    "recipe": "ops/image/recipe/Dockerfile",
    "apt_packages": "ops/image/recipe/apt-packages.txt",
    "python_requirements": "ops/image/recipe/python-requirements.txt",
    "capability_check": "ops/image/recipe/check-capabilities.sh",
}
RELEASE_README = b"ops/image/releases/README.md"
CAPABILITY_LINES = (
    "OK: representative research binaries are present",
    re.compile(r"OK: CPython [0-9]+\.[0-9]+\.[0-9]+ is the default research Python"),
    "OK: pinned Python scientific/data imports",
    "OK: ancillary Ubuntu Python imports",
    re.compile(r"OK: R [0-9]+\.[0-9]+\.[0-9]+ is installed"),
    "OK: R package manifest and session info are present",
    "OK: R analysis/document imports",
    "OK: version probes passed without network access",
)


class StrictLoader(yaml.SafeLoader):
    """Safe YAML with no aliases, anchors, duplicate keys, or custom tags."""

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None):
            raise yaml.constructor.ConstructorError(None, None, "anchors and aliases are not allowed", event.start_mark)
        node = super().compose_node(parent, index)
        if node.tag not in YAML_TAGS:
            raise yaml.constructor.ConstructorError(None, None, "unsupported YAML tag", node.start_mark)
        return node

    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False) -> dict[str, Any]:
        if not isinstance(node, yaml.nodes.MappingNode):
            raise yaml.constructor.ConstructorError(None, None, "mapping required", node.start_mark)
        result: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(None, None, "mapping keys must be strings", key_node.start_mark)
            if key in result:
                raise yaml.constructor.ConstructorError(None, None, "duplicate YAML key", key_node.start_mark)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class ValidationError(Exception):
    """Raised for an invalid release repository."""


@dataclass(frozen=True)
class ValidationReport:
    errors: tuple[str, ...]
    history_checked: bool


def _relative(root: Path, path: Path) -> str:
    """Return a repository-relative diagnostic without exposing host paths."""
    try:
        relative = path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError:
        relative = "<outside-repository>"
    return relative.encode("unicode_escape").decode("ascii")


def _add(errors: list[str], root: Path, path: Path, message: str) -> None:
    errors.append(f"{_relative(root, path)}: {message}")


def _no_symlink_components(root: Path, path: Path, errors: list[str]) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError:
        _add(errors, root, path, "path escapes repository")
        return False
    current = root
    if current.is_symlink():
        _add(errors, root, root, "repository root must not be a symlink")
        return False
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            _add(errors, root, path, "path has a symlinked parent component")
            return False
    return True


def _regular(path: Path, root: Path, errors: list[str]) -> bool:
    if not _no_symlink_components(root, path, errors):
        return False
    try:
        mode = path.lstat().st_mode
    except OSError:
        _add(errors, root, path, "must be an existing regular non-symlink file")
        return False
    if not stat.S_ISREG(mode):
        _add(errors, root, path, "must be an existing regular non-symlink file")
        return False
    return True


def _prohibited_text(text: str) -> str | None:
    if any((ord(char) < 32 and char not in "\n\t") or ord(char) == 127 for char in text):
        return "contains a prohibited control character"
    for marker in KNOWN_HOST_ROOTS:
        if marker in text:
            return "contains a prohibited host root"
    for pattern in SECRET_MARKERS:
        if pattern.search(text):
            return "contains a prohibited credential, token, session-cookie, JWT, or key pattern"
    for pattern in RAW_EVIDENCE_MARKERS:
        if pattern.search(text):
            return "contains a prohibited raw-live-evidence category"
    return None


def _scan_scalars(value: Any, root: Path, path: Path, errors: list[str]) -> None:
    if isinstance(value, str):
        message = _prohibited_text(value)
        if message:
            _add(errors, root, path, message)
    elif isinstance(value, bytes):
        _add(errors, root, path, "binary YAML scalar is not allowed")
    elif isinstance(value, dict):
        for key, child in value.items():
            _scan_scalars(key, root, path, errors)
            _scan_scalars(child, root, path, errors)
    elif isinstance(value, list):
        for child in value:
            _scan_scalars(child, root, path, errors)


def _parse_yaml_text(text: str, root: Path, path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = yaml.load(text, Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError):
        _add(errors, root, path, "cannot parse strict YAML")
        return None
    if not isinstance(value, dict):
        _add(errors, root, path, "top-level YAML value must be a mapping")
        return None
    _scan_scalars(value, root, path, errors)
    return value


def _load_yaml(path: Path, root: Path, errors: list[str]) -> dict[str, Any] | None:
    if not _regular(path, root, errors):
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _add(errors, root, path, "must be readable UTF-8 text")
        return None
    message = _prohibited_text(text)
    if message:
        _add(errors, root, path, message)
    return _parse_yaml_text(text, root, path, errors)


def _scan_text(path: Path, root: Path, errors: list[str]) -> str | None:
    if not _regular(path, root, errors):
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _add(errors, root, path, "must be readable UTF-8 text")
        return None
    message = _prohibited_text(text)
    if message:
        _add(errors, root, path, message)
    return text


def _hash(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _hash(value[7:])


def _commit(value: Any) -> bool:
    return isinstance(value, str) and bool(COMMIT40.fullmatch(value))


def _exact_mapping(value: Any, expected: set[str], label: str, root: Path, path: Path, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _add(errors, root, path, f"{label} must be a mapping")
        return None
    if set(value) != expected:
        _add(errors, root, path, f"{label} has missing or unknown keys")
    return value


def _safe_repo_file(root: Path, value: Any, errors: list[str], label: str) -> None:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        _add(errors, root, root / "ops/image/recipe", f"{label} must be a relative recipe path")
        return
    parsed = PurePosixPath(value)
    if value != parsed.as_posix() or any(part in {"", ".", ".."} for part in parsed.parts):
        _add(errors, root, root / "ops/image/recipe", f"{label} must be a safe relative recipe path")
        return
    if len(parsed.parts) < 4 or parsed.parts[:3] != ("ops", "image", "recipe"):
        _add(errors, root, root / "ops/image/recipe", f"{label} must be under ops/image/recipe")
        return
    _regular(root.joinpath(*parsed.parts), root, errors)


def _validate_recipe_provenance(
    root: Path,
    identity: dict[str, Any] | None,
    build_inputs: dict[str, Any] | None,
    path: Path,
    errors: list[str],
) -> None:
    if identity is None or build_inputs is None or not _commit(identity.get("profile_recipe_commit")):
        return
    commit = identity["profile_recipe_commit"]
    try:
        resolved = _git_bytes(root, "rev-parse", "--verify", f"{commit}^{{commit}}").decode("ascii").strip()
    except (ValidationError, UnicodeDecodeError):
        _add(errors, root, path, "profile_recipe_commit must resolve in the local Git repository")
        return
    if resolved != commit:
        _add(errors, root, path, "profile_recipe_commit must be a full resolved local commit")
        return
    try:
        _git_bytes(root, "merge-base", "--is-ancestor", commit, "HEAD")
    except ValidationError:
        _add(errors, root, path, "profile_recipe_commit must be an ancestor of HEAD")
        return
    for key, asset in CANONICAL_BUILD_INPUTS.items():
        if build_inputs.get(key) != asset:
            continue
        try:
            kind = _git_bytes(root, "cat-file", "-t", f"{commit}:{asset}").decode("ascii").strip()
        except (ValidationError, UnicodeDecodeError):
            _add(errors, root, path, f"build_inputs.{key} is not a blob at profile_recipe_commit")
            continue
        if kind != "blob":
            _add(errors, root, path, f"build_inputs.{key} is not a blob at profile_recipe_commit")
    try:
        dockerfile = _git_bytes(root, "show", f"{commit}:{CANONICAL_BUILD_INPUTS['recipe']}")
        matches = re.findall(rb"(?m)^ARG BASE_IMAGE=[^\n]*@(sha256:[0-9a-f]{64})\s*$", dockerfile)
    except (ValidationError, UnicodeDecodeError):
        _add(errors, root, path, "recipe Dockerfile blob is unavailable at profile_recipe_commit")
        return
    if len(matches) != 1:
        _add(errors, root, path, "recipe Dockerfile must contain exactly one pinned BASE_IMAGE digest")
    elif identity.get("base_image_digest") != matches[0].decode("ascii"):
        _add(errors, root, path, "identity.base_image_digest does not match the pinned recipe Dockerfile")


def _date_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _ordered_tsv(text: str, expected_header: tuple[str, ...], label: str, root: Path, path: Path, errors: list[str]) -> None:
    if "\r" in text:
        _add(errors, root, path, f"{label} must use LF TSV rows")
        return
    lines = text.splitlines()
    rows = [line.split("\t") for line in lines]
    if not rows or tuple(rows[0]) != expected_header:
        _add(errors, root, path, f"{label} has the wrong exact TSV header")
        return
    if len(rows) < 2 or any(len(row) != len(expected_header) or any(not cell for cell in row) for row in rows[1:]):
        _add(errors, root, path, f"{label} must contain nonempty rows with exact column counts")
        return
    names = [row[0] for row in rows[1:]]
    if any(not PACKAGE_NAME.fullmatch(name) for name in names):
        _add(errors, root, path, f"{label} contains an invalid package name")
    normalized = [_normal(name) for name in names]
    if len(normalized) != len(set(normalized)) or normalized != sorted(normalized):
        _add(errors, root, path, f"{label} package rows must be unique and deterministically sorted")


def _ordered_python(text: str, root: Path, path: Path, errors: list[str]) -> None:
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        _add(errors, root, path, "Python inventory must be nonempty with no blank lines")
        return
    names: list[str] = []
    for line in lines:
        match = PYTHON_PACKAGE.fullmatch(line)
        if not match:
            _add(errors, root, path, "Python inventory must contain exact name==version lines")
            continue
        names.append(_normal(match.group(1)))
    if len(names) != len(set(names)) or names != sorted(names):
        _add(errors, root, path, "Python inventory package rows must be unique and deterministically sorted")


def _session_info(text: str, root: Path, path: Path, errors: list[str]) -> None:
    if not text.strip() or not R_VERSION.search(text) or not re.search(r"^Platform:\s*\S", text, re.MULTILINE):
        _add(errors, root, path, "R sessionInfo must include a recognizable R version and Platform")
    marker = re.search(r"(?im)^attached base packages:\s*$", text)
    if marker is None or not re.search(r"(?i)\bbase\b", text[marker.end():]):
        _add(errors, root, path, "R sessionInfo must include attached base packages")


def _capability(text: str, root: Path, path: Path, errors: list[str]) -> None:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    valid = len(lines) == len(CAPABILITY_LINES) and all(
        (expected.fullmatch(actual) if hasattr(expected, "fullmatch") else expected == actual)
        for actual, expected in zip(lines, CAPABILITY_LINES)
    )
    if not valid:
        _add(errors, root, path, "capability output must contain exactly the eight canonical lines in order")


def _release_dirs(releases_dir: Path, root: Path, errors: list[str]) -> list[Path]:
    if not releases_dir.exists():
        _regular(releases_dir / "README.md", root, errors)
        return []
    if not _no_symlink_components(root, releases_dir, errors) or not releases_dir.is_dir():
        _add(errors, root, releases_dir, "release root must be a real directory")
        return []
    readme = releases_dir / "README.md"
    readme_valid = _regular(readme, root, errors)
    result: list[Path] = []
    try:
        children = sorted(releases_dir.iterdir())
    except OSError:
        _add(errors, root, releases_dir, "release root cannot be read")
        return []
    for child in children:
        if child == readme and readme_valid:
            continue
        if child.is_symlink() or not child.is_dir() or not RELEASE_ID.fullmatch(child.name):
            _add(errors, root, child, "must be a real release directory with an accepted release-id name")
            continue
        _no_symlink_components(root, child, errors)
        result.append(child)
    return result


def _release_contents(release_dir: Path, root: Path, errors: list[str]) -> None:
    expected = {"release.yaml", *EVIDENCE_KEYS.values()}
    try:
        children = list(release_dir.iterdir())
    except OSError:
        _add(errors, root, release_dir, "release directory cannot be read")
        return
    for child in children:
        if child.name not in expected:
            _add(errors, root, child, "release directory contains an undeclared file or directory")
    for name in sorted(expected):
        if not (release_dir / name).exists():
            _add(errors, root, release_dir / name, "required release file is missing")


def _validate_release(release_dir: Path, root: Path, errors: list[str]) -> None:
    _release_contents(release_dir, root, errors)
    release_yaml = release_dir / "release.yaml"
    data = _load_yaml(release_yaml, root, errors)
    if data is None:
        return
    if set(data) != TOP_KEYS:
        _add(errors, root, release_yaml, "release.yaml has missing or unknown top-level keys")
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        _add(errors, root, release_yaml, "schema_version must be integer 1")
    release_id = data.get("release_id")
    if release_id != release_dir.name or not isinstance(release_id, str) or not RELEASE_ID.fullmatch(release_id):
        _add(errors, root, release_yaml, "release_id must match its directory name")
    elif not _date_string(release_id[:10]):
        _add(errors, root, release_yaml, "release-id date prefix must be a real YYYY-MM-DD date")
    if data.get("status") != "accepted":
        _add(errors, root, release_yaml, "only status: accepted releases are allowed")
    if data.get("reproducibility") != "not_guaranteed":
        _add(errors, root, release_yaml, "reproducibility must be not_guaranteed")
    for key in ("accepted_at", "recorded_at"):
        if not _date_string(data.get(key)):
            _add(errors, root, release_yaml, f"{key} must be a YYYY-MM-DD string")
    if _date_string(data.get("accepted_at")) and _date_string(data.get("recorded_at")) and data["accepted_at"] == data["recorded_at"]:
        pass
    elif _date_string(data.get("accepted_at")) and _date_string(data.get("recorded_at")) and data["accepted_at"] > data["recorded_at"]:
        _add(errors, root, release_yaml, "accepted_at must not be after recorded_at")

    identity = _exact_mapping(data.get("identity"), IDENTITY_KEYS, "identity", root, release_yaml, errors)
    if identity is not None:
        if not _commit(identity.get("profile_recipe_commit")):
            _add(errors, root, release_yaml, "identity.profile_recipe_commit must be a full Git commit")
        if not _digest(identity.get("image_id")):
            _add(errors, root, release_yaml, "identity.image_id must be a full sha256 digest")
        if not _digest(identity.get("base_image_digest")):
            _add(errors, root, release_yaml, "identity.base_image_digest must be a full sha256 digest")

    build_inputs = _exact_mapping(data.get("build_inputs"), BUILD_INPUT_KEYS, "build_inputs", root, release_yaml, errors)
    if build_inputs is not None:
        for key in BUILD_INPUT_KEYS:
            if build_inputs.get(key) != CANONICAL_BUILD_INPUTS[key]:
                _add(errors, root, release_yaml, f"build_inputs.{key} must name the canonical recipe asset")
            _safe_repo_file(root, build_inputs.get(key), errors, f"build_inputs.{key}")

    hermes = _exact_mapping(data.get("hermes"), HERMES_KEYS, "hermes", root, release_yaml, errors)
    if hermes is not None:
        if not isinstance(hermes.get("version"), str) or not HERMES_VERSION.fullmatch(hermes["version"]):
            _add(errors, root, release_yaml, "hermes.version must match vN.N.N")
        if not isinstance(hermes.get("package"), str) or not NUMERIC_VERSION.fullmatch(hermes["package"]):
            _add(errors, root, release_yaml, "hermes.package must be a numeric dotted version")
        if not _commit(hermes.get("commit")):
            _add(errors, root, release_yaml, "hermes.commit must be a full Git commit")

    attestation = _exact_mapping(data.get("operator_attestation"), ATTESTATION_KEYS, "operator_attestation", root, release_yaml, errors)
    if attestation is not None:
        if attestation.get("image_manifest_correspondence") is not True or attestation.get("source") != "external-container-correlation":
            _add(errors, root, release_yaml, "operator_attestation has invalid required values")

    evidence = _exact_mapping(data.get("evidence"), set(EVIDENCE_KEYS), "evidence", root, release_yaml, errors)
    tracked = data.get("tracked_file_sha256")
    if not isinstance(tracked, dict) or set(tracked) != set(EVIDENCE_KEYS.values()):
        _add(errors, root, release_yaml, "tracked_file_sha256 must contain exactly the five evidence files")
        tracked = {}
    if evidence is None:
        return
    _validate_recipe_provenance(root, identity, build_inputs, release_yaml, errors)
    for key, expected_name in EVIDENCE_KEYS.items():
        declaration = _exact_mapping(evidence.get(key), {"file", "sha256"}, f"evidence.{key}", root, release_yaml, errors)
        if declaration is None:
            continue
        if declaration.get("file") != expected_name or not _hash(declaration.get("sha256")):
            _add(errors, root, release_yaml, f"evidence.{key} has an invalid filename or SHA-256 declaration")
        if tracked.get(expected_name) != declaration.get("sha256") or not _hash(tracked.get(expected_name)):
            _add(errors, root, release_yaml, f"tracked SHA-256 declaration for {expected_name} does not match evidence")
        evidence_path = release_dir / expected_name
        text = _scan_text(evidence_path, root, errors)
        if text is None:
            continue
        if _hash(declaration.get("sha256")) and _sha256(evidence_path) != declaration["sha256"]:
            _add(errors, root, evidence_path, "content hash does not match release.yaml")
        if key == "apt_packages":
            _ordered_tsv(text, ("Package", "Version", "Architecture"), "APT inventory", root, evidence_path, errors)
        elif key == "python_packages":
            _ordered_python(text, root, evidence_path, errors)
        elif key == "r_packages":
            _ordered_tsv(text, ("Package", "Version"), "R inventory", root, evidence_path, errors)
        elif key == "r_session_info":
            _session_info(text, root, evidence_path, errors)
        elif key == "capability_check":
            _capability(text, root, evidence_path, errors)


def _compatibility_data(data: Any, release_dirs: list[Path], root: Path, path: Path, errors: list[str]) -> None:
    if not isinstance(data, dict) or set(data) != {"schema_version", "current_release"} or data.get("schema_version") != 1:
        _add(errors, root, path, "must be a strict schema_version 1 release pointer/index")
        return
    current = data.get("current_release")
    names = {directory.name for directory in release_dirs}
    if not release_dirs:
        if current is not None:
            _add(errors, root, path, "current_release must be null while no accepted release exists")
    elif not isinstance(current, str) or current not in names:
        _add(errors, root, path, "current_release must name an existing accepted release")


def _validate_compatibility(root: Path, release_dirs: list[Path], errors: list[str]) -> None:
    path = root / "compatibility/hermes.yaml"
    data = _load_yaml(path, root, errors)
    if data is not None:
        _compatibility_data(data, release_dirs, root, path, errors)


def _git_bytes(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if result.returncode:
        raise ValidationError("git history operation failed")
    return result.stdout


def _nul_tokens(data: bytes) -> list[bytes]:
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise ValidationError("git path output was not NUL terminated")
    return data[:-1].split(b"\0")


def _release_dir_from_path(raw: bytes) -> str | None:
    prefix = b"ops/image/releases/"
    if raw == RELEASE_README:
        return None
    if not raw.startswith(prefix):
        return None
    name = raw[len(prefix):].split(b"/", 1)[0]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError:
        return None


def _check_git_path(raw: bytes, base_dirs: set[str], errors: list[str]) -> str | None:
    directory = _release_dir_from_path(raw)
    if directory is None and raw.startswith(b"ops/image/releases/"):
        if raw == RELEASE_README:
            return raw.decode("ascii")
        errors.append("trusted base: release path uses prohibited non-ASCII encoding")
        return None
    if directory is None:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    unusual = any(byte >= 128 for byte in raw) or any(byte in raw for byte in b'\t\n\r"\\')
    if directory in base_dirs and unusual:
        errors.append("trusted base: existing release path uses prohibited quoting, control, or non-ASCII bytes")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _diff_paths(data: bytes) -> list[tuple[bytes, list[bytes]]]:
    tokens = _nul_tokens(data)
    result: list[tuple[bytes, list[bytes]]] = []
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        count = 2 if status[:1] in {b"R", b"C"} else 1
        if index + count > len(tokens):
            raise ValidationError("git diff path output was malformed")
        result.append((status, tokens[index:index + count]))
        index += count
    return result


def _check_diff(root: Path, base: str, base_dirs: set[str], errors: list[str], cached: bool) -> None:
    args = ["diff"]
    if cached:
        args.append("--cached")
    args += ["--name-status", "-z", "--find-renames", base, "--", "ops/image/releases"]
    try:
        records = _diff_paths(_git_bytes(root, *args))
    except ValidationError:
        errors.append("trusted base: Git diff path output was malformed")
        return
    for status, paths in records:
        for raw in paths:
            path = _check_git_path(raw, base_dirs, errors)
            if path is not None and _release_dir_from_path(raw) in base_dirs and status[:1] in b"MDRAC":
                errors.append("trusted base: an existing release directory has a staged or worktree change")


def _check_nul_paths(data: bytes, base_dirs: set[str], errors: list[str]) -> set[str]:
    try:
        paths = _nul_tokens(data)
    except ValidationError:
        errors.append("trusted base: Git path output was malformed")
        return set()
    result: set[str] = set()
    for raw in paths:
        path = _check_git_path(raw, base_dirs, errors)
        if path is not None:
            result.add(path)
    return result


def _history_check(root: Path, errors: list[str], requested_base: str) -> bool:
    try:
        base_bytes = _git_bytes(root, "rev-parse", "--verify", f"{requested_base}^{{commit}}")
        base = base_bytes.decode("ascii").strip()
    except (ValidationError, UnicodeDecodeError):
        errors.append("trusted base revision is invalid or unavailable")
        return True
    if not COMMIT40.fullmatch(base):
        errors.append("trusted base did not resolve to a full commit")
        return True
    try:
        base_files = _check_nul_paths(_git_bytes(root, "ls-tree", "-r", "--name-only", "-z", base, "--", "ops/image/releases"), set(), errors)
    except ValidationError:
        errors.append("trusted base: Git tree path output was unavailable")
        return True
    base_dirs = {directory for path in base_files if (directory := _release_dir_from_path(path.encode())) is not None}
    _check_diff(root, base, base_dirs, errors, cached=True)
    _check_diff(root, base, base_dirs, errors, cached=False)
    staged_paths: set[str] = set()
    try:
        staged_paths = _check_nul_paths(
            _git_bytes(root, "diff", "--cached", "--name-only", "-z", "--", "compatibility/hermes.yaml", "ops/image/releases"),
            base_dirs,
            errors,
        )
        index_worktree = _check_nul_paths(
            _git_bytes(root, "diff", "--name-only", "-z", "--", "compatibility/hermes.yaml", "ops/image/releases"),
            base_dirs,
            errors,
        )
        overlap = staged_paths & index_worktree
        relevant_overlap = {
            path for path in overlap
            if path == "compatibility/hermes.yaml" or _release_dir_from_path(path.encode()) in base_dirs
        }
        if relevant_overlap:
            errors.append("trusted base: index and worktree release state differ")
    except ValidationError:
        errors.append("trusted base: index/worktree path output was unavailable")

    for args in (
        ("ls-files", "--others", "--exclude-standard", "-z", "--", "ops/image/releases"),
        ("ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "ops/image/releases"),
    ):
        try:
            _check_nul_paths(_git_bytes(root, *args), base_dirs, errors)
        except ValidationError:
            errors.append("trusted base: untracked/ignored path output was unavailable")

    try:
        staged = staged_paths
        if "compatibility/hermes.yaml" in staged:
            staged_data = _parse_yaml_text(
                _git_bytes(root, "show", ":compatibility/hermes.yaml").decode("utf-8"),
                root,
                root / "compatibility/hermes.yaml",
                errors,
            )
            if staged_data is not None:
                release_dirs = _release_dirs(root / "ops/image/releases", root, errors)
                _compatibility_data(staged_data, release_dirs, root, root / "compatibility/hermes.yaml", errors)
    except (ValidationError, UnicodeDecodeError):
        errors.append("trusted base: staged pointer state was unavailable or invalid")
    _validate_staged_candidate(root, errors)
    return True


def _validate_staged_candidate(root: Path, errors: list[str]) -> None:
    """Validate the index tree, not only the possibly different worktree."""
    try:
        with tempfile.TemporaryDirectory(dir=root, prefix=".u3-index-") as directory:
            snapshot = Path(directory)
            result = subprocess.run(
                ["git", "-C", str(root), "checkout-index", "--all", "--prefix", f"{snapshot}{'/'}"],
                capture_output=True,
                check=False,
            )
            if result.returncode:
                raise ValidationError("git index checkout failed")
            report = validate_repository(snapshot)
    except (OSError, ValidationError):
        errors.append("trusted base: staged candidate tree was unavailable")
        return
    errors.extend(f"staged candidate: {error}" for error in report.errors)


def validate_repository(root: Path, base: str | None = None) -> ValidationReport:
    root = root.resolve()
    errors: list[str] = []
    release_dirs = _release_dirs(root / "ops/image/releases", root, errors)
    _validate_compatibility(root, release_dirs, errors)
    for release_dir in release_dirs:
        _validate_release(release_dir, root, errors)
    history_checked = False
    if base is not None:
        history_checked = _history_check(root, errors, base)
    return ValidationReport(tuple(errors), history_checked)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate accepted Peirce image release evidence.")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root (default: .)")
    parser.add_argument("--base", help="trusted Git revision for append-only release history checks")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = validate_repository(args.root, args.base)
    if report.errors:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if report.history_checked:
        print("validation passed: schema/content and trusted-base append-only checks")
    else:
        print("validation passed: schema/content checks; append-only history not checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
