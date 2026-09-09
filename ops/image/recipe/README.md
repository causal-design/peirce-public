# Peirce broad research image recipe

This recipe is an illustrative, credential-free compute image recipe for a
Hermes-compatible Peirce deployment. It is not evidence of a built or deployed
image. Python and R, system libraries, compilers, document
tools, CLIs, TeX, graphics, diagrams, spreadsheets, archives, OCR, media
helpers, local Git, and ordinary outbound internet belong here rather than in
the Hermes agent environment. It adds no credentials, cloud authentication,
browser automation, or runtime package installer.

## Build

The default base is the reviewed multi-architecture Ubuntu 24.04 manifest
`ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`.
Override it only with another reviewed digest-pinned value:

```sh
docker build \
  --build-arg BASE_IMAGE=ubuntu@sha256:<reviewed-ubuntu-24.04-digest> \
  --build-arg TZ=Etc/UTC \
  -t hermes-research:<reviewed-tag> .
```

Build context must be this `recipe/` directory. The image installs Ubuntu-
packaged dependencies listed in `apt-packages.txt`. CPython 3.14.7 is built from
the official source archive
`https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tgz`, verified against
SHA256 `62859805f6fdf25e2bcbf3fa3217801e1996887ca33e6a2af80674bdfa2dbe07`, and
the pinned Python requirements are installed at image build time. This is a
standard non-PGO source build selected for predictable rebuild time. R is
installed from the official signed CRAN Noble repository at package revision
`4.6.1-2.2404.0`; the Dockerfile verifies the CRAN signing key fingerprint
`E298 A3A8 25C0 D65D FD57 CBB6 5171 6619 E084 DAB9` before use.
After R is installed, exactly `data.table`, `dplyr`, `ggplot2`, `jsonlite`,
`knitr`, `rmarkdown`, `readxl`, and `yaml` are source-installed from CRAN with
the default dependency classes and two-way compilation parallelism. `tidyverse`
and `ragg` are intentionally absent. The sorted installed-package manifest and
R `sessionInfo()` are retained at
`/opt/hermes-research/r-package-manifest.tsv` and
`/opt/hermes-research/r-sessionInfo.txt`.
The package set is broad and therefore trades image size and build time for
fewer recurring project setup steps. Do not add a package-management framework,
lock, drain controller, or extra manifest for hypothetical dependencies; add
only the smallest mechanism needed when an actual package requires it.

The research Python is installed under `/opt/cpython/3.14.7`; `/usr/local/bin/python`,
`python3`, `pip`, and `pip3` resolve to it, while `/usr/bin/python3` remains the
Ubuntu OS Python for ancillary apt libraries. Neither this image nor its build
changes the Hermes gateway virtual environment.

## Capability check

After a build, run the provider-free check inside the image:

```sh
docker run --rm hermes-research:<reviewed-tag> hermes-image-check
```

The check uses no network and verifies representative shell/Git/SSH, TeX and
bibliography, document/PDF, graphics/diagram, spreadsheet/archive, OCR/media,
Python imports, and R imports. It does not claim universal tool coverage or
activate runtime plugins.

## Operator adaptation

Build and test each candidate under a unique immutable tag in an operator-owned
environment. The check is provider-free and does not prove that an image was
built, promoted, selected by Hermes, or used by a live deployment. Operators
must independently choose their image tag, runtime integration, host policy,
and replacement procedure.

Do not build directly over `current`, delete the prior candidate, or add secrets
or fake offline/egress controls. The runtime remains ordinary and high-trust,
with network behavior controlled by the stock Hermes deployment.
