# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Official registry index SHA read on 2026-10-07; build Linux amd64 in CI and locally.
FROM --platform=linux/amd64 python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
ENV DEBIAN_FRONTEND=noninteractive AWS_PAGER="" PYTHONDONTWRITEBYTECODE=1
# Snapshot pins package resolution; no personal AWS/Git/SSH credentials are copied.
RUN rm /etc/apt/sources.list.d/debian.sources && \
    printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261007T000000Z/ bookworm main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261007T000000Z/ bookworm-security main\n' > /etc/apt/sources.list && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends ca-certificates curl git openssh-client bash unzip xz-utils jq make && \
    rm -rf /var/lib/apt/lists/*
COPY toolchain.lock.json requirements.lock install_locked_tools.py /opt/tooling/
RUN python /opt/tooling/install_locked_tools.py && \
    pip install --no-cache-dir --require-hashes -r /opt/tooling/requirements.lock
WORKDIR /workspace
CMD ["bash"]
