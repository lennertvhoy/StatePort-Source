FROM docker.io/library/node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8 AS web-build
WORKDIR /web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --ignore-scripts --audit=false --fund=false \
    --fetch-retries=5 --fetch-retry-mintimeout=10000 --fetch-retry-maxtimeout=120000
COPY apps/web ./
ARG STATEPORT_BUILD_SOURCE_COMMIT=unknown
ARG STATEPORT_BUILD_SOURCE_TREE=unknown
ARG STATEPORT_BUILD_SOURCE_REF=unknown
ARG STATEPORT_BUILD_SOURCE_DIRTY=true
ARG STATEPORT_BUILD_SOURCE_DATE_EPOCH=unknown
ARG STATEPORT_BUILD_VERSION=0.0.0-unknown
# The vite build contract validates the full provenance set. Dirty defaults
# to true so an unlabelled build can never present itself as a clean one.
ENV STATEPORT_BUILD_SOURCE_COMMIT=${STATEPORT_BUILD_SOURCE_COMMIT} \
    STATEPORT_BUILD_SOURCE_TREE=${STATEPORT_BUILD_SOURCE_TREE} \
    STATEPORT_BUILD_SOURCE_REF=${STATEPORT_BUILD_SOURCE_REF} \
    STATEPORT_BUILD_SOURCE_DIRTY=${STATEPORT_BUILD_SOURCE_DIRTY} \
    STATEPORT_BUILD_SOURCE_DATE_EPOCH=${STATEPORT_BUILD_SOURCE_DATE_EPOCH} \
    STATEPORT_BUILD_VERSION=${STATEPORT_BUILD_VERSION}
RUN npm run build

FROM docker.io/library/python:3.13-alpine3.23@sha256:9fdbf2e3e82628351513560b121e2ee6ce31cac212be9e070c5a5e2769fb5e76
ARG STATEPORT_BUILD_SOURCE_COMMIT=unknown
ARG STATEPORT_BUILD_SOURCE_TREE=unknown
ARG STATEPORT_BUILD_SOURCE_REF=unknown
ARG STATEPORT_BUILD_SOURCE_DIRTY=true
ARG STATEPORT_BUILD_SOURCE_DATE_EPOCH=unknown
ARG STATEPORT_BUILD_VERSION=0.0.0-unknown
ARG STATEPORT_BUILD_CREATED=1970-01-01T00:00:00Z
ARG STATEPORT_BUILD_ADAPTER=unknown
LABEL org.opencontainers.image.title="StatePort Web" \
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
      io.stateport.image.role="control-web" \
      io.stateport.component.preview-gateway="same-origin-web-process" \
      io.stateport.packaged-content="stateport.packaged-content/v1" \
      io.stateport.provider.executables="none"

# The AppServer validates the exact runtime Git identity of the mounted
# product root (_validate_product_root) and executes approved filesystem
# transactions through Bubblewrap, so the runtime image needs Git and
# Bubblewrap and nothing else from the system package set. The Alpine 3.23
# Git package links only musl, libcurl (OpenSSL backend), libexpat, PCRE2,
# and zlib; unlike the Debian package it has no Perl dependency chain.
# libcrypto3/libssl3/sqlite-libs are exact-pinned upgrades of base-image
# packages to the currently published v3.23 security releases; the pins fail
# closed when the repositories roll forward, so a later rebuild can never
# silently drift to unreviewed bytes.
RUN apk add --no-cache \
      git=2.52.0-r0 \
      bubblewrap=0.12.0-r0 \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
      sqlite-libs=3.53.4-r0 \
    && rm -f /var/log/apk.log \
    && git config --system --add safe.directory /workspace
COPY requirements/runtime-linux-amd64.txt /tmp/stateport-runtime-requirements.txt
COPY images/bin/stateport-healthcheck /usr/local/bin/stateport-healthcheck
# pip compiles bytecode at install time; any package built from an sdist
# embeds fresh source mtimes in its .pyc files, which breaks OCI two-build
# digest reproducibility. SOURCE_DATE_EPOCH makes CPython emit deterministic
# hash-based .pyc files instead.
RUN if [ "${STATEPORT_BUILD_SOURCE_DATE_EPOCH}" != "unknown" ]; then \
      export SOURCE_DATE_EPOCH="${STATEPORT_BUILD_SOURCE_DATE_EPOCH}"; \
    fi; \
    python3 -m pip install --disable-pip-version-check --no-cache-dir --require-hashes \
      -r /tmp/stateport-runtime-requirements.txt \
    && rm /tmp/stateport-runtime-requirements.txt \
    && chmod 0555 /usr/local/bin/stateport-healthcheck \
    && mkdir -p /workspace /var/lib/stateport/config /var/lib/stateport/data /var/lib/stateport/state \
    && chown -R 65532:65532 /workspace /var/lib/stateport
WORKDIR /workspace

# Final-image product content is an exact positive allowlist mirrored by
# images/packaged-content.v1.yaml. No repository, Git, instance, runtime, or
# private root is copied wholesale.
COPY VERSION /workspace/VERSION
COPY apps/admin-cli/src /workspace/apps/admin-cli/src
COPY apps/runner/src /workspace/apps/runner/src
COPY apps/telegram-adapter/src /workspace/apps/telegram-adapter/src
COPY apps/web/container-service.py /workspace/apps/web/container-service.py
COPY apps/web/package.json apps/web/package-lock.json /workspace/apps/web/
COPY config/application-experience-policy.yaml /workspace/config/application-experience-policy.yaml
COPY config/context-lifecycle.v1.yaml /workspace/config/context-lifecycle.v1.yaml
COPY config/functionality-preservation.v1.yaml /workspace/config/functionality-preservation.v1.yaml
COPY config/statespec-schema-registry.v1.json /workspace/config/statespec-schema-registry.v1.json
COPY packages/api-auth/src /workspace/packages/api-auth/src
COPY packages/api-native-adapter/src /workspace/packages/api-native-adapter/src
COPY packages/application-experience/src /workspace/packages/application-experience/src
COPY packages/approval-gate/src /workspace/packages/approval-gate/src
COPY packages/audit-log/src /workspace/packages/audit-log/src
COPY packages/codex-adapter/src /workspace/packages/codex-adapter/src
COPY packages/container-opencode/src /workspace/packages/container-opencode/src
COPY packages/container-runner/src /workspace/packages/container-runner/src
COPY packages/context-lifecycle/src /workspace/packages/context-lifecycle/src
COPY packages/contribution-bundle/src /workspace/packages/contribution-bundle/src
COPY packages/contribution-bundle-v2/src /workspace/packages/contribution-bundle-v2/src
COPY packages/conversation-service/src /workspace/packages/conversation-service/src
COPY packages/deployment/src /workspace/packages/deployment/src
COPY packages/diagnostics/src /workspace/packages/diagnostics/src
COPY packages/execution-host/src /workspace/packages/execution-host/src
COPY packages/external-engine-runtime/src /workspace/packages/external-engine-runtime/src
COPY packages/file-workspace-broker/src /workspace/packages/file-workspace-broker/src
COPY packages/goal-execution/src /workspace/packages/goal-execution/src
COPY packages/governed-api/src /workspace/packages/governed-api/src
COPY packages/governed-runner/src /workspace/packages/governed-runner/src
COPY packages/instance-backup/src /workspace/packages/instance-backup/src
COPY packages/instance-catalog/src /workspace/packages/instance-catalog/src
COPY packages/lifecycle-migrations/src /workspace/packages/lifecycle-migrations/src
COPY packages/observability/src /workspace/packages/observability/src
COPY packages/opencode-adapter/src /workspace/packages/opencode-adapter/src
COPY packages/persistent-app/src /workspace/packages/persistent-app/src
COPY packages/portable-execution/src /workspace/packages/portable-execution/src
COPY packages/preview-gateway/src /workspace/packages/preview-gateway/src
COPY packages/quota-engine/src /workspace/packages/quota-engine/src
COPY packages/release-contracts/src /workspace/packages/release-contracts/src
COPY packages/run-bundle/src /workspace/packages/run-bundle/src
COPY packages/runtime-contracts/src /workspace/packages/runtime-contracts/src
COPY packages/sandbox-runtime/src /workspace/packages/sandbox-runtime/src
COPY packages/sensitive-data-gateway/src /workspace/packages/sensitive-data-gateway/src
COPY packages/statebench/src /workspace/packages/statebench/src
COPY packages/statedd-core/src /workspace/packages/statedd-core/src
COPY packages/stateport-compat/src /workspace/packages/stateport-compat/src
COPY packages/template-validator/src /workspace/packages/template-validator/src
COPY packages/terminal-broker/src /workspace/packages/terminal-broker/src
COPY packages/tool-gateway/src /workspace/packages/tool-gateway/src
COPY packages/updater/src /workspace/packages/updater/src
COPY schemas /workspace/schemas
COPY fixtures/application-experiences/checklist-state.yaml /workspace/fixtures/application-experiences/checklist-state.yaml
COPY fixtures/application-experiences/development-workspace.yaml /workspace/fixtures/application-experiences/development-workspace.yaml
COPY fixtures/application-experiences/study-state.yaml /workspace/fixtures/application-experiences/study-state.yaml
COPY fixtures/application-experiences/studystate-sample.yaml /workspace/fixtures/application-experiences/studystate-sample.yaml
COPY fixtures/apps/checklistdd /workspace/fixtures/apps/checklistdd
COPY fixtures/apps/development-reference /workspace/fixtures/apps/development-reference
COPY fixtures/apps/studystate-sample /workspace/fixtures/apps/studystate-sample
COPY fixtures/apps/synthetic-reference /workspace/fixtures/apps/synthetic-reference
COPY fixtures/host/synthetic-capabilities.json /workspace/fixtures/host/synthetic-capabilities.json
COPY sources/canonical/studydd.yaml /workspace/sources/canonical/studydd.yaml
COPY sources/profiles/studydd-local-alpha.yaml /workspace/sources/profiles/studydd-local-alpha.yaml
COPY --from=web-build /web/dist /workspace/apps/web/dist

# The AppServer validates the exact runtime Git identity of the product root
# (_validate_product_root). Source-build compose overmounts the checkout's
# .git for that; the no-checkout packaged image instead carries its own
# synthesized commit of the exact packaged tree. Fixed identity and
# timestamps keep the commit byte-reproducible across the two-build proof,
# and the message binds the exact private source identity it was cut from.
# `apk add` writes a wall-clock line to /var/log/apk.log and the Git index
# embeds host inode/stat data; both break two-build OCI digest equality, so
# the layer deletes the log and rebuilds the index from HEAD without stat
# information (read-tree writes zero-stat cache entries; status still
# verifies content on demand).
RUN git -C /workspace init -q \
    && git -C /workspace config user.name "StatePort Packaged Product" \
    && git -C /workspace config user.email "packaged@stateport.invalid" \
    && git -C /workspace add -A \
    && GIT_AUTHOR_DATE="${STATEPORT_BUILD_CREATED}" \
      GIT_COMMITTER_DATE="${STATEPORT_BUILD_CREATED}" \
      git -C /workspace commit -q \
      -m "packaged product content ${STATEPORT_BUILD_VERSION}" \
      -m "source-commit: ${STATEPORT_BUILD_SOURCE_COMMIT}" \
      -m "source-tree: ${STATEPORT_BUILD_SOURCE_TREE}" \
    && rm /workspace/.git/index \
    && git -C /workspace read-tree HEAD \
    && chmod -R a-w /workspace/.git

ENV HOME=/var/lib/stateport \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/var/lib/stateport/config \
    XDG_DATA_HOME=/var/lib/stateport/data \
    XDG_STATE_HOME=/var/lib/stateport/state \
    STATEPORT_PACKAGED_PRODUCT=1 \
    STATEPORT_PRODUCT_ROOT=/workspace \
    STATEPORT_BUILD_SOURCE_COMMIT=${STATEPORT_BUILD_SOURCE_COMMIT} \
    STATEPORT_BUILD_SOURCE_TREE=${STATEPORT_BUILD_SOURCE_TREE}
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/usr/local/bin/stateport-healthcheck", "--kind", "http", "--host", "127.0.0.1", "--port", "8080", "--path", "/health"]
CMD ["python3", "/workspace/apps/web/container-service.py", "--port", "8080", "--repo-root", "/workspace", "--host", "0.0.0.0", "--allow-public-bind", "--actor-role", "platform_operator"]
