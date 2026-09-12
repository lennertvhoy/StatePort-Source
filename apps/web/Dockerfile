ARG STATEPORT_PROVIDER_IMAGE=stateport-provider-empty
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

# Codex remains the supported provider. Install only the locked native runtime
# in the control service that actually owns assistant execution; no Node/npm,
# credentials or provider session state enter the final image.
FROM docker.io/library/node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8 AS stateport-provider-empty
RUN mkdir -p /out
ARG STATEPORT_PROVIDER_IMAGE=stateport-provider-empty
FROM ${STATEPORT_PROVIDER_IMAGE} AS stateport-provider
FROM docker.io/library/node:22-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8 AS provider-build
WORKDIR /provider
ARG STATEPORT_PROVIDER_MODE=official-npm
ARG STATEPORT_PROVIDER_MANIFEST_DIGEST=
ARG STATEPORT_PROVIDER_PLATFORM_MANIFEST_DIGEST=
ARG STATEPORT_PROVIDER_VERSION=
ARG STATEPORT_PROVIDER_BUBBLEWRAP_VERSION=
ARG STATEPORT_PROVIDER_RIPGREP_VERSION=
ARG STATEPORT_PROVIDER_SOURCE_COMMIT=
ARG STATEPORT_PROVIDER_SOURCE_ARCHIVE_DIGEST=
ARG STATEPORT_PROVIDER_BUILD_CONTEXT_DIGEST=
ARG STATEPORT_PROVIDER_CODEX_DIGEST=
ARG STATEPORT_PROVIDER_BUBBLEWRAP_DIGEST=
ARG STATEPORT_PROVIDER_RIPGREP_DIGEST=
COPY config/codex-runtime/package.json config/codex-runtime/package-lock.json ./
RUN --mount=type=bind,from=stateport-provider,source=/out,target=/provider-input,readonly \
    set -eu \
    && rm -rf /out \
    && mkdir /out \
    && if [ "$STATEPORT_PROVIDER_MODE" = official-npm ]; then \
         npm ci --ignore-scripts --omit=dev --audit=false --fund=false \
         && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex /out/codex \
         && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-path/rg /out/rg \
         && chmod 0555 /out/codex /out/rg \
         && /out/codex --version | grep -Fx "codex-cli 0.146.0"; \
       elif [ "$STATEPORT_PROVIDER_MODE" = custom-oci ]; then \
         export STATEPORT_PROVIDER_MANIFEST_DIGEST STATEPORT_PROVIDER_PLATFORM_MANIFEST_DIGEST STATEPORT_PROVIDER_VERSION \
           STATEPORT_PROVIDER_BUBBLEWRAP_VERSION STATEPORT_PROVIDER_RIPGREP_VERSION \
           STATEPORT_PROVIDER_SOURCE_COMMIT STATEPORT_PROVIDER_SOURCE_ARCHIVE_DIGEST \
           STATEPORT_PROVIDER_BUILD_CONTEXT_DIGEST STATEPORT_PROVIDER_CODEX_DIGEST \
           STATEPORT_PROVIDER_BUBBLEWRAP_DIGEST STATEPORT_PROVIDER_RIPGREP_DIGEST; \
         test -f /provider-input/provider-metadata.json \
           && test -x /provider-input/codex \
           && test -x /provider-input/bwrap \
           && test -x /provider-input/rg \
           && node -e 'const fs=require("fs"),m=JSON.parse(fs.readFileSync("/provider-input/provider-metadata.json")),d=/^sha256:[0-9a-f]{64}$/; const a=m.artifacts||{},s=m.source||{}; if(m.formatVersion!=="stateport.provider-runtime-metadata/v1"||m.version!==process.env.STATEPORT_PROVIDER_VERSION||m.bubblewrapVersion!==process.env.STATEPORT_PROVIDER_BUBBLEWRAP_VERSION||m.ripgrepVersion!==process.env.STATEPORT_PROVIDER_RIPGREP_VERSION||s.repository!=="https://github.com/openai/codex"||s.commit!==process.env.STATEPORT_PROVIDER_SOURCE_COMMIT||s.sourceArchiveDigest!==process.env.STATEPORT_PROVIDER_SOURCE_ARCHIVE_DIGEST||s.buildContextDigest!==process.env.STATEPORT_PROVIDER_BUILD_CONTEXT_DIGEST||!d.test(a.codex?.digest)||!d.test(a.bubblewrap?.digest)||!d.test(a.ripgrep?.digest)||a.codex?.digest!==process.env.STATEPORT_PROVIDER_CODEX_DIGEST||a.bubblewrap?.digest!==process.env.STATEPORT_PROVIDER_BUBBLEWRAP_DIGEST||a.ripgrep?.digest!==process.env.STATEPORT_PROVIDER_RIPGREP_DIGEST||!Array.isArray(m.licenses)||m.licenses.join(",")!=="LICENSE,NOTICE,BUBBLEWRAP-LICENSE,BUBBLEWRAP-NOTICE") process.exit(1)' \
           && test "$(sha256sum /provider-input/codex | cut -d' ' -f1)" = "${STATEPORT_PROVIDER_CODEX_DIGEST#sha256:}" \
           && test "$(sha256sum /provider-input/bwrap | cut -d' ' -f1)" = "${STATEPORT_PROVIDER_BUBBLEWRAP_DIGEST#sha256:}" \
           && test "$(sha256sum /provider-input/rg | cut -d' ' -f1)" = "${STATEPORT_PROVIDER_RIPGREP_DIGEST#sha256:}" \
           && test "$(/provider-input/codex --version)" = "$STATEPORT_PROVIDER_VERSION" \
           && test "$(/provider-input/bwrap --version | head -n1)" = "$STATEPORT_PROVIDER_BUBBLEWRAP_VERSION" \
           && test "$(/provider-input/rg --version | head -n1)" = "$STATEPORT_PROVIDER_RIPGREP_VERSION" \
           && for license in LICENSE NOTICE BUBBLEWRAP-LICENSE BUBBLEWRAP-NOTICE; do test -f "/provider-input/$license"; cp "/provider-input/$license" "/out/$license"; done \
           && cp /provider-input/codex /out/codex \
           && cp /provider-input/bwrap /out/bwrap \
           && cp /provider-input/rg /out/rg \
           && chmod 0555 /out/codex /out/bwrap /out/rg; \
       else \
         echo "unsupported provider input mode" >&2; exit 1; \
       fi

FROM docker.io/library/python:3.13-alpine3.23@sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01
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
      io.stateport.provider.executables="codex"

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
      libuuid=2.41.6-r1 \
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
# This directory is deliberately outside StatePort data/config/backup roots.
# The signed topology supplies a provider-owned mount; without it read-only
# container roots refuse authentication instead of writing auth into product data.
RUN mkdir -p /var/lib/stateport-provider/codex \
    && chown 65532:65532 /var/lib/stateport-provider/codex \
    && chmod 0700 /var/lib/stateport-provider/codex
COPY --from=provider-build /out/codex /usr/local/bin/codex
COPY --from=provider-build /out/rg /usr/local/bin/rg
COPY --from=provider-build /out /tmp/stateport-provider-inputs
ARG STATEPORT_PROVIDER_MODE=official-npm
RUN if [ "$STATEPORT_PROVIDER_MODE" = custom-oci ]; then \
      install -m 0555 /tmp/stateport-provider-inputs/bwrap /usr/bin/bwrap \
      && install -d -m 0555 /usr/share/licenses/stateport-provider \
      && install -m 0444 /tmp/stateport-provider-inputs/LICENSE /usr/share/licenses/stateport-provider/LICENSE \
      && install -m 0444 /tmp/stateport-provider-inputs/NOTICE /usr/share/licenses/stateport-provider/NOTICE \
      && install -m 0444 /tmp/stateport-provider-inputs/BUBBLEWRAP-LICENSE /usr/share/licenses/stateport-provider/BUBBLEWRAP-LICENSE \
      && install -m 0444 /tmp/stateport-provider-inputs/BUBBLEWRAP-NOTICE /usr/share/licenses/stateport-provider/BUBBLEWRAP-NOTICE; \
    fi \
    && rm -rf /tmp/stateport-provider-inputs
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
COPY fixtures/application-experiences/managed-projectstate.yaml /workspace/fixtures/application-experiences/managed-projectstate.yaml
COPY fixtures/application-experiences/managed-studystate.yaml /workspace/fixtures/application-experiences/managed-studystate.yaml
COPY fixtures/application-experiences/managed-template.yaml /workspace/fixtures/application-experiences/managed-template.yaml
COPY fixtures/application-experiences/study-state.yaml /workspace/fixtures/application-experiences/study-state.yaml
COPY fixtures/application-experiences/studystate-sample.yaml /workspace/fixtures/application-experiences/studystate-sample.yaml
COPY fixtures/apps/checklistdd /workspace/fixtures/apps/checklistdd
COPY fixtures/apps/development-reference /workspace/fixtures/apps/development-reference
COPY fixtures/apps/studystate-sample /workspace/fixtures/apps/studystate-sample
COPY fixtures/apps/synthetic-reference /workspace/fixtures/apps/synthetic-reference
COPY fixtures/host/synthetic-capabilities.json /workspace/fixtures/host/synthetic-capabilities.json
COPY fixtures/template-adapters /workspace/fixtures/template-adapters
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
    CODEX_HOME=/var/lib/stateport-provider/codex \
    STATEPORT_PACKAGED_PRODUCT=1 \
    STATEPORT_PRODUCT_ROOT=/workspace \
    STATEPORT_BUILD_SOURCE_COMMIT=${STATEPORT_BUILD_SOURCE_COMMIT} \
    STATEPORT_BUILD_SOURCE_TREE=${STATEPORT_BUILD_SOURCE_TREE}
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/usr/local/bin/stateport-healthcheck", "--kind", "http", "--host", "127.0.0.1", "--port", "8080", "--path", "/health"]
CMD ["python3", "/workspace/apps/web/container-service.py", "--port", "8080", "--repo-root", "/workspace", "--host", "0.0.0.0", "--allow-public-bind", "--actor-role", "platform_operator"]
