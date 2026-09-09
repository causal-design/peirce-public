# SPDX-License-Identifier: AGPL-3.0-only
# Broad, non-secret research terminal image for stock Hermes.
# Verified multi-architecture Ubuntu 24.04 manifest; override only with another
# reviewed digest-pinned base.
ARG BASE_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
FROM ${BASE_IMAGE}

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=Etc/UTC
ARG CPYTHON_VERSION=3.14.7
ARG CPYTHON_SHA256=62859805f6fdf25e2bcbf3fa3217801e1996887ca33e6a2af80674bdfa2dbe07
ARG CRAN_R_APT_VERSION=4.6.1-2.2404.0
ARG CRAN_KEY_FINGERPRINT=E298A3A825C0D65DFD57CBB651716619E084DAB9

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=${TZ} \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY apt-packages.txt /tmp/hermes-image-apt-packages.txt

# Bootstrap the OS, verify the official CRAN key, install pinned R, and clean
# apt state before the more frequently changing source-build layers.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates curl gawk gnupg locales tzdata \
    && ln --symbolic --force "/usr/share/zoneinfo/${TZ}" /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata \
    && locale-gen C.UTF-8 \
    && update-locale LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    && curl --fail --location --silent --show-error \
        https://cloud.r-project.org/bin/linux/ubuntu/marutter_pubkey.asc \
        --output /tmp/marutter_pubkey.asc \
    && actual_fingerprint="$(gpg --show-keys --with-colons /tmp/marutter_pubkey.asc \
        | gawk -F: '$1 == "fpr" { print toupper($10); exit }')" \
    && test "${actual_fingerprint}" = "${CRAN_KEY_FINGERPRINT}" \
    && mkdir --parents /usr/share/keyrings \
    && gpg --dearmor --output /usr/share/keyrings/cran-archive-keyring.gpg \
        /tmp/marutter_pubkey.asc \
    && printf '%s\n' \
        'deb [signed-by=/usr/share/keyrings/cran-archive-keyring.gpg] https://cloud.r-project.org/bin/linux/ubuntu noble-cran40/' \
        > /etc/apt/sources.list.d/cran.list \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        "r-base=${CRAN_R_APT_VERSION}" \
        "r-base-core=${CRAN_R_APT_VERSION}" \
        "r-base-dev=${CRAN_R_APT_VERSION}" \
        "r-recommended=${CRAN_R_APT_VERSION}" \
    && sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' \
        /tmp/hermes-image-apt-packages.txt \
        | xargs --no-run-if-empty apt-get install --yes --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/hermes-image-apt-packages.txt \
        /tmp/marutter_pubkey.asc

# Install the required CRAN source packages and retain immutable evidence.
RUN mkdir --parents /opt/hermes-research \
    && Rscript --vanilla -e 'required <- c("data.table", "dplyr", "ggplot2", "jsonlite", "knitr", "rmarkdown", "readxl", "yaml"); install.packages(required, repos = "https://cloud.r-project.org", type = "source", Ncpus = 2); missing <- required[!vapply(required, requireNamespace, logical(1), quietly = TRUE)]; if (length(missing)) stop("failed to install required R packages: ", paste(missing, collapse = ", "))' \
    && Rscript --vanilla -e 'installed <- as.data.frame(installed.packages(), stringsAsFactors = FALSE); manifest <- installed[order(installed$Package, installed$Version), c("Package", "Version")]; write.table(manifest, "/opt/hermes-research/r-package-manifest.tsv", row.names = FALSE, col.names = TRUE, quote = FALSE, sep = "\t"); writeLines(capture.output(sessionInfo()), "/opt/hermes-research/r-sessionInfo.txt")' \
    && chmod 0444 /opt/hermes-research/r-package-manifest.tsv \
        /opt/hermes-research/r-sessionInfo.txt

COPY python-requirements.txt /tmp/hermes-image-python-requirements.txt

# Build standard CPython, install the pinned Python stack, and remove sources.
RUN python_archive="/tmp/Python-${CPYTHON_VERSION}.tgz" \
    && curl --fail --location --silent --show-error \
        "https://www.python.org/ftp/python/${CPYTHON_VERSION}/Python-${CPYTHON_VERSION}.tgz" \
        --output "${python_archive}" \
    && printf '%s  %s\n' "${CPYTHON_SHA256}" "${python_archive}" \
        | sha256sum --check - \
    && tar --extract --gzip --file "${python_archive}" --directory /tmp \
    && cd "/tmp/Python-${CPYTHON_VERSION}" \
    && ./configure --prefix="/opt/cpython/${CPYTHON_VERSION}" \
        --with-ensurepip=install \
    && make --jobs="$(nproc)" \
    && make altinstall \
    && /opt/cpython/${CPYTHON_VERSION}/bin/python3.14 -m pip install \
        --disable-pip-version-check --no-cache-dir \
        --requirement /tmp/hermes-image-python-requirements.txt \
    && ln --symbolic --force \
        "/opt/cpython/${CPYTHON_VERSION}/bin/python3.14" /usr/local/bin/python \
    && ln --symbolic --force \
        "/opt/cpython/${CPYTHON_VERSION}/bin/python3.14" /usr/local/bin/python3 \
    && ln --symbolic --force \
        "/opt/cpython/${CPYTHON_VERSION}/bin/pip3.14" /usr/local/bin/pip \
    && ln --symbolic --force \
        "/opt/cpython/${CPYTHON_VERSION}/bin/pip3.14" /usr/local/bin/pip3 \
    && rm -rf /tmp/hermes-image-python-requirements.txt \
        "/tmp/Python-${CPYTHON_VERSION}" "${python_archive}"

COPY check-capabilities.sh /usr/local/bin/hermes-image-check

WORKDIR /srv/hermes/workspace

# Hermes supplies the terminal runtime/user boundary. This image deliberately
# adds no credentials, cloud configuration, browser automation, Node ecosystem,
# runtime package installer, or network policy shim.
