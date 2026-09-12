FROM docker.io/library/python:3.13-alpine3.23@sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01

ARG STATEPORT_BUILD_SOURCE_COMMIT=unknown
ARG STATEPORT_BUILD_SOURCE_TREE=unknown
ARG STATEPORT_BUILD_SOURCE_REF=unknown
ARG STATEPORT_BUILD_SOURCE_DIRTY=true
ARG STATEPORT_BUILD_SOURCE_DATE_EPOCH=unknown
ARG STATEPORT_BUILD_VERSION=0.0.0-unknown
ARG STATEPORT_BUILD_CREATED=1970-01-01T00:00:00Z
ARG STATEPORT_BUILD_ADAPTER=unknown
LABEL org.opencontainers.image.title="StatePort Runner" \
      org.opencontainers.image.source="https://github.com/lennertvhoy/StatePort" \
      org.opencontainers.image.revision="${STATEPORT_BUILD_SOURCE_COMMIT}" \
      org.opencontainers.image.version="${STATEPORT_BUILD_VERSION}" \
      org.opencontainers.image.created="${STATEPORT_BUILD_CREATED}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      io.stateport.source.tree="${STATEPORT_BUILD_SOURCE_TREE}" \
      org.opencontainers.image.ref.name="${STATEPORT_BUILD_SOURCE_REF}" \
      io.stateport.source.dirty="${STATEPORT_BUILD_SOURCE_DIRTY}" \
      io.stateport.source-date-epoch="${STATEPORT_BUILD_SOURCE_DATE_EPOCH}" \
      io.stateport.build.adapter="${STATEPORT_BUILD_ADAPTER}" \
      io.stateport.image.role="application-runner" \
      io.stateport.packaged-content="stateport.packaged-content/v1"

COPY requirements/runtime-linux-amd64.txt /tmp/stateport-runtime-requirements.txt
COPY images/bin/stateport-healthcheck /usr/local/bin/stateport-healthcheck
# Exact-pinned upgrade of base-image packages to the currently published
# Alpine 3.23 security releases; the pins fail closed when the repositories
# roll forward, so a later rebuild can never silently drift to unreviewed
# bytes. `apk add` writes a wall-clock line to /var/log/apk.log; deleting it
# keeps the two-build OCI digest proof reproducible.
RUN apk add --no-cache \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
      libuuid=2.41.6-r1 \
      sqlite-libs=3.53.4-r0 \
    && rm -f /var/log/apk.log

# SOURCE_DATE_EPOCH makes pip-compiled .pyc files deterministic (see
# apps/web/Dockerfile python-deps stage); sdist-built packages otherwise
# embed fresh source mtimes and break two-build reproducibility.
RUN if [ "${STATEPORT_BUILD_SOURCE_DATE_EPOCH}" != "unknown" ]; then \
      export SOURCE_DATE_EPOCH="${STATEPORT_BUILD_SOURCE_DATE_EPOCH}"; \
    fi; \
    python3 -m pip install --disable-pip-version-check --no-cache-dir --require-hashes \
      -r /tmp/stateport-runtime-requirements.txt \
    && rm /tmp/stateport-runtime-requirements.txt \
    && chmod 0555 /usr/local/bin/stateport-healthcheck \
    && mkdir -p /stateport /var/lib/stateport \
    && chown -R 65532:65532 /stateport /var/lib/stateport

WORKDIR /stateport
COPY packages/statedd-core/src /stateport/packages/statedd-core/src
COPY packages/template-validator/src /stateport/packages/template-validator/src
COPY schemas /stateport/schemas
COPY config/statespec-schema-registry.v1.json /stateport/config/statespec-schema-registry.v1.json
COPY apps/runner/src /stateport/apps/runner/src

ENV HOME=/var/lib/stateport \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/stateport/packages/statedd-core/src:/stateport/packages/template-validator/src:/stateport/apps/runner/src \
    STATEPORT_TEMPLATE_PATH=/stateport/template
USER 65532:65532
CMD ["python3", "-m", "runner", "/stateport/instance"]
