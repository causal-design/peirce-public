# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import yaml

from fixtures import add_release, make_repo, refresh_hashes


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "validate-release.py"
SPEC = importlib.util.spec_from_file_location("validate_release", VALIDATOR_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def errors(root: Path, base: str | None = None) -> tuple[str, ...]:
    return validator.validate_repository(root, base).errors


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def commit_fixture(root: Path) -> str:
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


def test_valid_fixture_passes_without_history_claim(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    report = validator.validate_repository(root)
    assert report.errors == ()
    assert report.history_checked is False


def test_cli_help_is_available() -> None:
    result = subprocess.run([sys.executable, str(VALIDATOR_PATH), "--help"], check=True, capture_output=True, text=True)
    assert "trusted Git revision" in result.stdout


def test_missing_field_and_bad_hash_fail(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
    data = yaml.safe_load(release.read_text(encoding="utf-8"))
    del data["hermes"]["commit"]
    data["identity"]["image_id"] = "sha256:bad"
    release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    result = errors(root)
    assert any("hermes.commit" in item for item in result)
    assert any("image_id" in item for item in result)


def test_release_id_date_and_recording_order_rules(tmp_path: Path) -> None:
    impossible = make_repo(tmp_path / "impossible", release_id="2026-02-30-impossible")
    assert any("real YYYY-MM-DD" in item for item in errors(impossible))

    equal = make_repo(tmp_path / "equal")
    release = equal / "ops/image/releases/2026-08-09-fixture/release.yaml"
    data = yaml.safe_load(release.read_text(encoding="utf-8"))
    data["recorded_at"] = data["accepted_at"]
    release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert not any("accepted_at must not be after" in item for item in errors(equal))

    reversed_dates = make_repo(tmp_path / "reversed")
    release = reversed_dates / "ops/image/releases/2026-08-09-fixture/release.yaml"
    data = yaml.safe_load(release.read_text(encoding="utf-8"))
    data["accepted_at"], data["recorded_at"] = "2026-08-10", "2026-08-09"
    release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert any("accepted_at must not be after" in item for item in errors(reversed_dates))


def test_unknown_or_missing_nested_keys_fail(tmp_path: Path) -> None:
    mutations = (
        ("top", lambda data: data.__setitem__("unknown", True)),
        ("identity", lambda data: data["identity"].pop("image_id")),
        ("build", lambda data: data["build_inputs"].__setitem__("extra", "x")),
        ("hermes", lambda data: data["hermes"].__setitem__("extra", "x")),
        ("attestation", lambda data: data["operator_attestation"].pop("source")),
        ("evidence", lambda data: data["evidence"].__setitem__("extra", {})),
        ("declaration", lambda data: data["evidence"]["apt_packages"].__setitem__("extra", "x")),
        ("tracked", lambda data: data["tracked_file_sha256"].__setitem__("extra", "0" * 64)),
    )
    for name, mutate in mutations:
        root = make_repo(tmp_path / name)
        release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
        data = yaml.safe_load(release.read_text(encoding="utf-8"))
        mutate(data)
        release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        assert errors(root), name


def test_unsorted_apt_python_and_r_inventories_fail(tmp_path: Path) -> None:
    for filename in ("apt-packages.tsv", "python-packages.txt", "r-packages.tsv"):
        root = make_repo(tmp_path / filename.replace(".", "-"))
        path = root / "ops/image/releases/2026-08-09-fixture" / filename
        lines = path.read_text(encoding="utf-8").splitlines()
        if filename == "python-packages.txt":
            reordered = list(reversed(lines))
        else:
            reordered = [lines[0], *reversed(lines[1:])]
        path.write_text("\n".join(reordered) + "\n", encoding="utf-8")
        refresh_hashes(root)
        result = errors(root)
        assert any("sorted" in item for item in result), (filename, result)


def test_legitimate_image_paths_pass_and_prohibited_content_fails(tmp_path: Path) -> None:
    legitimate = make_repo(tmp_path / "legitimate")
    assert not errors(legitimate)
    for index, content in enumerate((
        "path: /srv/hermes/private\n",
        "credential_path: /tmp/private.pem\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "raw container log\n",
    )):
        root = make_repo(tmp_path / f"bad-{index}")
        path = root / "ops/image/releases/2026-08-09-fixture/r-session-info.txt"
        path.write_text(content, encoding="utf-8")
        refresh_hashes(root)
        assert errors(root), content


def test_credential_markers_are_rejected_in_yaml_and_hashed_evidence(tmp_path: Path) -> None:
    for index, marker in enumerate((
        "ghs_secret",
        "gho_secret",
        "ghu_secret",
        "ghr_secret",
        "Bearer opaque-token",
        '{"AWS_SECRET_ACCESS_KEY":"opaque-secret"}',
    )):
        root = make_repo(tmp_path / f"evidence-secret-{index}")
        path = root / "ops/image/releases/2026-08-09-fixture/r-session-info.txt"
        path.write_text(path.read_text(encoding="utf-8") + marker + "\n", encoding="utf-8")
        refresh_hashes(root)
        assert errors(root), marker

    for index, (relative, marker) in enumerate((
        ("ops/image/releases/2026-08-09-fixture/release.yaml", '# {"AWS_SECRET_ACCESS_KEY":"opaque-secret"}\n'),
        ("compatibility/hermes.yaml", "# Authorization: Bearer opaque-token\n"),
    )):
        root = make_repo(tmp_path / f"yaml-secret-{index}")
        path = root / relative
        path.write_text(path.read_text(encoding="utf-8") + marker, encoding="utf-8")
        assert errors(root), relative


def test_capability_output_requires_the_exact_canonical_grammar(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    path = root / "ops/image/releases/2026-08-09-fixture/capability-check.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = "OK: arbitrary capability output"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    refresh_hashes(root)
    assert any("exactly the eight canonical lines" in item for item in errors(root))


def test_null_pointer_and_pointer_mismatch_rules(tmp_path: Path) -> None:
    empty = make_repo(tmp_path / "empty", release_id=None)
    assert not errors(empty)

    root = make_repo(tmp_path / "pointer")
    pointer = root / "compatibility/hermes.yaml"
    pointer.write_text(yaml.safe_dump({"schema_version": 1, "current_release": None}), encoding="utf-8")
    assert any("must name an existing" in item for item in errors(root))
    pointer.write_text(yaml.safe_dump({"schema_version": 1, "current_release": "2026-08-09-fixture"}), encoding="utf-8")
    assert not errors(root)
    pointer.write_text(yaml.safe_dump({"schema_version": 1, "current_release": "wrong"}), encoding="utf-8")
    assert any("must name an existing" in item for item in errors(root))


def test_release_hermes_fields_are_authoritative(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
    data = yaml.safe_load(release.read_text(encoding="utf-8"))
    data["hermes"]["version"] = "v2027.1.0"
    release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert not errors(root)


def test_trusted_base_rejects_existing_changes_and_allows_new_release(tmp_path: Path) -> None:
    for action in ("modify", "delete", "rename", "add"):
        root = make_repo(tmp_path / action)
        base = commit_fixture(root)
        release = root / "ops/image/releases/2026-08-09-fixture"
        if action == "modify":
            (release / "capability-check.txt").write_text("changed\n", encoding="utf-8")
        elif action == "delete":
            (release / "capability-check.txt").unlink()
        elif action == "rename":
            (release / "capability-check.txt").rename(release / "renamed.txt")
        else:
            (release / "new-file.txt").write_text("new\n", encoding="utf-8")
            git(root, "add", "ops/image/releases/2026-08-09-fixture/new-file.txt")
        result = errors(root, base)
        assert any("existing release directory" in item for item in result), (action, result)

    allowed = make_repo(tmp_path / "new-release")
    base = commit_fixture(allowed)
    add_release(allowed, "2026-08-10-candidate")
    report = validator.validate_repository(allowed, base)
    assert report.history_checked is True
    assert report.errors == ()


def test_release_readme_is_required_and_only_exact_file_is_exempt(tmp_path: Path) -> None:
    for kind in ("missing", "directory", "symlink", "nested"):
        root = make_repo(tmp_path / kind)
        readme = root / "ops/image/releases/README.md"
        if kind == "missing":
            readme.unlink()
        elif kind == "directory":
            readme.unlink()
            readme.mkdir()
        elif kind == "symlink":
            target = root / "readme-target"
            target.write_text("target\n", encoding="utf-8")
            readme.unlink()
            readme.symlink_to(target)
        else:
            (root / "ops/image/releases/2026-08-09-fixture/README.md").write_text("nested\n", encoding="utf-8")
        assert errors(root), kind

        base = commit_fixture(make_repo(tmp_path / f"base-{kind}"))
        base_root = (tmp_path / f"base-{kind}") / "repo"
        base_readme = base_root / "ops/image/releases/README.md"
        if kind == "missing":
            base_readme.unlink()
        elif kind == "directory":
            base_readme.unlink()
            base_readme.mkdir()
        elif kind == "symlink":
            target = base_root / "readme-target"
            target.write_text("target\n", encoding="utf-8")
            base_readme.unlink()
            base_readme.symlink_to(target)
        else:
            (base_root / "ops/image/releases/2026-08-09-fixture/README.md").write_text("nested\n", encoding="utf-8")
        assert errors(base_root, base), kind


def test_future_candidate_matching_evidence_passes_and_mismatch_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path / "future")
    add_release(root, "2026-08-10-candidate", image_character="e")
    assert not errors(root)
    candidate = root / "ops/image/releases/2026-08-10-candidate/python-packages.txt"
    candidate.write_text("numpy==9.9.9\npandas==3.0.5\n", encoding="utf-8")
    assert errors(root)


def test_recipe_provenance_requires_reachable_commit_and_matching_blobs(tmp_path: Path) -> None:
    for name, mutate in (
        ("nonexistent", lambda root, data: data["identity"].__setitem__("profile_recipe_commit", "f" * 40)),
        ("unrelated", None),
        ("missing-blob", "missing-blob"),
        ("digest", lambda root, data: data["identity"].__setitem__("base_image_digest", "sha256:" + "d" * 64)),
    ):
        root = make_repo(tmp_path / name)
        release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
        data = yaml.safe_load(release.read_text(encoding="utf-8"))
        if name == "unrelated":
            git(root, "checkout", "--orphan", "unrelated")
            git(root, "commit", "--allow-empty", "-m", "unrelated")
            unrelated = git(root, "rev-parse", "HEAD")
            git(root, "checkout", "main")
            data["identity"]["profile_recipe_commit"] = unrelated
        elif name == "missing-blob":
            (root / "ops/image/recipe/Dockerfile").unlink()
            git(root, "add", "ops/image/recipe/Dockerfile")
            git(root, "commit", "-m", "remove recipe blob")
            data["identity"]["profile_recipe_commit"] = git(root, "rev-parse", "HEAD")
        else:
            assert callable(mutate)
            mutate(root, data)
        release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        assert any("profile_recipe_commit" in item or "base_image_digest" in item for item in errors(root)), name


def test_release_directory_has_exact_regular_file_set(tmp_path: Path) -> None:
    for kind in ("extra", "nested", "symlink", "parent-symlink", "binary"):
        root = make_repo(tmp_path / kind)
        release = root / "ops/image/releases/2026-08-09-fixture"
        if kind == "extra":
            (release / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        elif kind == "nested":
            (release / "nested").mkdir()
        elif kind == "symlink":
            target = root / "outside.txt"
            target.write_text("target\n", encoding="utf-8")
            (release / "capability-check.txt").unlink()
            (release / "capability-check.txt").symlink_to(target)
        elif kind == "parent-symlink":
            releases = root / "ops/image/releases"
            real = root / "ops/image/releases-real"
            releases.rename(real)
            releases.symlink_to(real, target_is_directory=True)
        else:
            (release / "capability-check.txt").write_bytes(b"\xff\x00")
            refresh_hashes(root)
        assert errors(root), kind


def test_strict_yaml_rejects_duplicate_alias_tag_binary_and_scalar_secrets(tmp_path: Path) -> None:
    invalid_yaml = (
        "schema_version: 1\nschema_version: 1\n",
        "schema_version: &one 1\ncopy: *one\n",
        "schema_version: !custom 1\n",
        "schema_version: !!binary |\n  AQI=\n",
    )
    for index, content in enumerate(invalid_yaml):
        root = make_repo(tmp_path / f"yaml-{index}")
        (root / "ops/image/releases/2026-08-09-fixture/release.yaml").write_text(content, encoding="utf-8")
        assert errors(root), content
    for index, value in enumerate((
        "session-cookie: abc",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        "credential_path: /etc/hermes/secret",
    )):
        root = make_repo(tmp_path / f"scalar-{index}")
        release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
        data = yaml.safe_load(release.read_text(encoding="utf-8"))
        data["operator_attestation"]["source"] = value
        release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        assert errors(root), value


def test_malformed_and_empty_evidence_fails_with_refreshed_hashes(tmp_path: Path) -> None:
    invalid = {
        "apt-packages.tsv": "Package\tVersion\n",
        "python-packages.txt": "not-a-package-line\n",
        "r-packages.tsv": "Package\tVersion\n",
        "r-session-info.txt": "",
        "capability-check.txt": "FAIL: broken\n",
    }
    for index, (filename, content) in enumerate(invalid.items()):
        root = make_repo(tmp_path / f"evidence-{index}")
        path = root / "ops/image/releases/2026-08-09-fixture" / filename
        path.write_text(content, encoding="utf-8")
        refresh_hashes(root)
        assert errors(root), filename


def test_build_input_shape_and_recipe_symlink_fail(tmp_path: Path) -> None:
    root = make_repo(tmp_path / "build-inputs")
    release = root / "ops/image/releases/2026-08-09-fixture/release.yaml"
    data = yaml.safe_load(release.read_text(encoding="utf-8"))
    del data["build_inputs"]["apt_packages"]
    data["build_inputs"]["unknown"] = "ops/image/recipe/Dockerfile"
    release.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    assert errors(root)

    root = make_repo(tmp_path / "build-symlink")
    recipe = root / "ops/image/recipe/Dockerfile"
    real = root / "real-dockerfile"
    real.write_text("fixture\n", encoding="utf-8")
    recipe.unlink()
    recipe.symlink_to(real)
    assert errors(root)


def test_readme_update_is_allowed_by_trusted_base(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    base = commit_fixture(root)
    readme = root / "ops/image/releases/README.md"
    readme.write_text("updated documentation\n", encoding="utf-8")
    git(root, "add", "ops/image/releases/README.md")
    readme.write_text("updated documentation again\n", encoding="utf-8")
    report = validator.validate_repository(root, base)
    assert report.history_checked is True
    assert not report.errors


def test_cli_accepts_a_fully_staged_new_release_and_pointer_with_base(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    base = commit_fixture(root)
    add_release(root, "2026-08-10-candidate")
    git(root, "add", "ops/image/releases/2026-08-10-candidate", "compatibility/hermes.yaml")
    result = subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), "--root", str(root), "--base", base],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "trusted-base" in result.stdout


def test_staged_pointer_and_existing_release_mutations_fail(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    base = commit_fixture(root)
    pointer = root / "compatibility/hermes.yaml"
    pointer.write_text("schema_version: 1\ncurrent_release: wrong\n", encoding="utf-8")
    git(root, "add", "compatibility/hermes.yaml")
    pointer.write_text("schema_version: 1\ncurrent_release: 2026-08-09-fixture\n", encoding="utf-8")
    result = errors(root, base)
    assert any("index and worktree" in item for item in result)

    root = make_repo(tmp_path / "staged-release")
    base = commit_fixture(root)
    capability = root / "ops/image/releases/2026-08-09-fixture/capability-check.txt"
    capability.write_text("changed\n", encoding="utf-8")
    git(root, "add", str(capability.relative_to(root)))
    capability.write_text("OK: capability checks passed\n", encoding="utf-8")
    assert any("existing release directory" in item for item in errors(root, base))


def test_staged_new_release_is_validated_as_the_index_candidate(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    base = commit_fixture(root)
    add_release(root, "2026-08-10-candidate")
    release = root / "ops/image/releases/2026-08-10-candidate/release.yaml"
    valid = release.read_text(encoding="utf-8")
    release.write_text(valid.replace("status: accepted", "status: planned"), encoding="utf-8")
    git(root, "add", str(release.relative_to(root)))
    release.write_text(valid, encoding="utf-8")
    result = errors(root, base)
    assert any("staged candidate" in item and "status: accepted" in item for item in result)


def test_unusual_staged_untracked_and_ignored_paths_fail_closed(tmp_path: Path) -> None:
    for index, (name, staged, ignored) in enumerate((
        ("staged\tname", True, False),
        ("untracked\nname", False, False),
        ('quoted"name', False, False),
        ("ignored\tname", False, True),
    )):
        root = make_repo(tmp_path / f"unusual-{index}")
        base = commit_fixture(root)
        if ignored:
            ignore = root / ".gitignore"
            ignore.write_text("ops/image/releases/2026-08-09-fixture/ignored*\n", encoding="utf-8")
            git(root, "add", ".gitignore")
            git(root, "commit", "-m", "fixture ignore")
        path = root / "ops/image/releases/2026-08-09-fixture" / name
        path.write_text("noise\n", encoding="utf-8")
        if staged:
            git(root, "add", "-A")
        result = errors(root, base)
        assert any("prohibited" in item for item in result), (name, result)


def test_cli_valid_no_base_trusted_base_and_invalid_base(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    valid = subprocess.run([sys.executable, str(VALIDATOR_PATH), "--root", str(root)], capture_output=True, text=True)
    assert valid.returncode == 0 and "history not checked" in valid.stdout
    base = commit_fixture(root)
    trusted = subprocess.run([sys.executable, str(VALIDATOR_PATH), "--root", str(root), "--base", base], capture_output=True, text=True)
    assert trusted.returncode == 0 and "trusted-base" in trusted.stdout
    invalid = subprocess.run([sys.executable, str(VALIDATOR_PATH), "--root", str(root), "--base", "not-a-revision"], capture_output=True, text=True)
    assert invalid.returncode != 0 and "invalid or unavailable" in invalid.stderr
