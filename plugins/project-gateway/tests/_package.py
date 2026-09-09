# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


PLUGIN = Path(__file__).resolve().parents[1]
PACKAGE = "project_gateway_tested"
MANIFEST = (PLUGIN / "plugin.yaml").read_text(encoding="utf-8").splitlines()
ENTRYPOINT = next(
    line.split(":", 1)[1].strip()
    for line in MANIFEST
    if line.startswith("entrypoint:")
)

gateway = sys.modules.get(PACKAGE)
if gateway is None:
    spec = importlib.util.spec_from_file_location(
        PACKAGE, PLUGIN / ENTRYPOINT, submodule_search_locations=[str(PLUGIN)])
    assert spec and spec.loader
    gateway = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = gateway
    spec.loader.exec_module(gateway)

cli_runner = gateway.cli_runner
github = gateway.github
host_boundary = gateway.host_boundary
project = gateway.project
registry = gateway.registry
project_git = sys.modules[f"{PACKAGE}.git"]
