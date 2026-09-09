#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

ok() {
    printf 'OK: %s\n' "$*"
}

expected_python_version='3.14.7'
expected_python_bin='/opt/cpython/3.14.7/bin/python3.14'
expected_pip_bin='/opt/cpython/3.14.7/bin/pip3.14'
expected_r_version='4.6.1'
r_evidence_dir='/opt/hermes-research'
r_manifest="$r_evidence_dir/r-package-manifest.tsv"
r_session_info="$r_evidence_dir/r-sessionInfo.txt"

for binary in \
    git ssh python python3 pip pip3 R Rscript \
    pdflatex xelatex lualatex latexmk bibtex biber \
    pandoc libreoffice pdftotext qpdf gs dot gnuplot \
    convert tesseract ffmpeg 7z unzip; do
    command -v "$binary" >/dev/null || fail "missing binary: $binary"
done
ok 'representative research binaries are present'

for launcher in /usr/local/bin/python /usr/local/bin/python3; do
    [ "$(readlink -f "$launcher")" = "$expected_python_bin" ] \
        || fail "$launcher does not resolve to CPython 3.14.7"
done
for launcher in /usr/local/bin/pip /usr/local/bin/pip3; do
    [ "$(readlink -f "$launcher")" = "$expected_pip_bin" ] \
        || fail "$launcher does not resolve to CPython 3.14.7 pip"
done
[ "$(readlink -f /usr/bin/python3)" != "$expected_python_bin" ] \
    || fail '/usr/bin/python3 was replaced by the research Python'

python_version="$(python3 -c 'import platform; print(platform.python_version())')"
[ "$python_version" = "$expected_python_version" ] \
    || fail "expected Python $expected_python_version, got $python_version"
ok "CPython $python_version is the default research Python"

python3 - <<'PY'
import importlib
from importlib.metadata import version

expected = {
    "numpy": "2.5.1",
    "pandas": "3.0.5",
    "scipy": "1.18.0",
    "matplotlib": "3.11.1",
    "sympy": "1.14.0",
    "statsmodels": "0.14.6",
    "sklearn": "1.9.0",
    "openpyxl": "3.1.5",
    "odf": "1.4.1",
}
distributions = {
    "numpy": "numpy",
    "pandas": "pandas",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "sympy": "sympy",
    "statsmodels": "statsmodels",
    "sklearn": "scikit-learn",
    "openpyxl": "openpyxl",
    "odf": "odfpy",
}
for module, expected_version in expected.items():
    importlib.import_module(module)
    actual_version = version(distributions[module])
    if actual_version != expected_version:
        raise RuntimeError(f"{distributions[module]} {actual_version} != {expected_version}")
print("OK: pinned Python scientific/data imports")
PY

# These ancillary libraries remain Ubuntu-packaged and available to the OS
# Python; the research Python above is intentionally a separate installation.
/usr/bin/python3 - <<'PY'
import importlib

for name in ("lxml", "bs4", "yaml", "PIL", "requests"):
    importlib.import_module(name)
print("OK: ancillary Ubuntu Python imports")
PY

R_version="$(R --version | gawk 'NR == 1 { print $3; exit }')"
[ "$R_version" = "$expected_r_version" ] \
    || fail "expected R $expected_r_version, got $R_version"
ok "R $R_version is installed"
[ -s "$r_manifest" ] || fail "missing R package manifest: $r_manifest"
[ -s "$r_session_info" ] || fail "missing R session info: $r_session_info"
ok 'R package manifest and session info are present'

Rscript --vanilla - <<'RSCRIPT'
stopifnot(as.character(getRversion()) == "4.6.1")
required <- c("data.table", "dplyr", "ggplot2", "jsonlite", "knitr", "rmarkdown", "readxl", "yaml")
missing <- required[!vapply(required, requireNamespace, logical(1), quietly = TRUE)]
if (length(missing)) {
    stop(paste("missing required R namespaces:", paste(missing, collapse = ", ")))
}
if (!isTRUE(rmarkdown::pandoc_available())) {
    stop("rmarkdown::pandoc_available() is false")
}
example <- readxl::read_xlsx(readxl::readxl_example("datasets.xlsx"))
if (!nrow(example) || !ncol(example)) {
    stop("bundled readxl example is empty")
}
forbidden <- c("tidyverse", "ragg")
present <- forbidden[vapply(forbidden, requireNamespace, logical(1), quietly = TRUE)]
if (length(present)) {
    stop(paste("forbidden R namespaces are installed:", paste(present, collapse = ", ")))
}
manifest <- read.delim("/opt/hermes-research/r-package-manifest.tsv", stringsAsFactors = FALSE)
if (!all(required %in% manifest$Package)) {
    stop("R package manifest does not contain every required package")
}
RSCRIPT

Rscript --vanilla - <<'RSCRIPT'
packages <- c("data.table", "dplyr", "ggplot2", "jsonlite", "knitr", "rmarkdown", "readxl", "yaml")
missing <- packages[!vapply(packages, requireNamespace, logical(1), quietly = TRUE)]
if (length(missing)) {
    stop(paste("missing R packages:", paste(missing, collapse = ", ")))
}
cat("OK: R analysis/document imports\n")
RSCRIPT

python3 -m pip --version >/dev/null
R --version >/dev/null
pdflatex --version >/dev/null
xelatex --version >/dev/null
lualatex --version >/dev/null
libreoffice --headless --version >/dev/null
ok 'version probes passed without network access'
