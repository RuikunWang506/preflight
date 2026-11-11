# The lookfirst sandbox image (SPEC section 8). It's built on your computer the first time
# `lookfirst check --sandbox` runs, or with `lookfirst sandbox build`. No target is in it:
# each run copies the target into a fresh container, and removes the container afterwards.
#
# Debian 13 "trixie" slim, pinned by digest (an index covering arm64 and amd64).
FROM debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# What installs commonly need, plus strace (to see what an install does) and procps.
# Installed from Debian on your computer; lookfirst ships only this recipe. Licenses are
# listed in THIRD_PARTY.md (git, gcc, strace and procps are GPL or LGPL).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git curl ca-certificates python3 python3-pip python3-venv nodejs npm \
      build-essential strace procps \
 && rm -rf /var/lib/apt/lists/*

# uv, pinned to a release that was at least 14 days old when it was pinned.
RUN pip install --break-system-packages --no-cache-dir uv==0.13.6

# Every lookfirst test fixture checks for this file before doing anything.
RUN touch /.lookfirst-sandbox

# An ordinary user owns the project folder, the home folder and a Python environment
# for `pip install`. Nothing in a run is root.
RUN useradd --create-home --uid 1000 --shell /bin/bash sandbox \
 && mkdir -p /work /opt/lookfirst-venv \
 && chown sandbox:sandbox /work /opt/lookfirst-venv \
 && su sandbox -s /bin/sh -c "python3 -m venv /opt/lookfirst-venv"

ENV PATH=/opt/lookfirst-venv/bin:/home/sandbox/.npm-global/bin:/usr/local/bin:/usr/bin:/bin \
    NPM_CONFIG_PREFIX=/home/sandbox/.npm-global \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LANG=C.UTF-8
USER sandbox
WORKDIR /work
