# Preparation-only consumer build. Context must come from consumer_context.py.
FROM docker.io/library/rust:1.95.0-alpine3.23@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
RUN apk add --no-cache build-base=0.5-r3 cmake=4.1.3-r0 \
      clang21=21.1.2-r2 clang21-libclang=21.1.2-r2 \
      lld21=21.1.2-r1 lld21-libs=21.1.2-r1 scudo-malloc=21.1.2-r0 \
      git=2.52.0-r0 linux-headers=6.16.12-r0 openssl-dev=3.5.8-r0 \
      perl=5.42.2-r0 pkgconf=2.5.1-r0 python3=3.12.14-r0 \
      openssl-libs-static=3.5.8-r0 zlib-static=1.3.2-r0 bzip2-static=1.0.8-r6 \
      xz-static=5.8.3-r0 brotli-static=1.2.0-r0 zstd-static=1.5.7-r2
WORKDIR /build
COPY . /build/context/
WORKDIR /build/context/codex-rs
ARG STATEPORT_CONTEXT_RECEIPT_SHA256
RUN test -n "$STATEPORT_CONTEXT_RECEIPT_SHA256" \
    && echo "$STATEPORT_CONTEXT_RECEIPT_SHA256  ../consumer-context.json" | sha256sum -c - \
    && verifier=$(python3 -c 'import json; print(json.load(open("../consumer-context.json"))["contextVerifierSha256"])') \
    && echo "$verifier  ../context_verify.py" | sha256sum -c - \
    && digest=$(python3 -c 'import json; print(json.load(open("../consumer-context.json"))["inventoryDigest"])') \
    && python3 ../context_verify.py .. --sha "$digest"
ENV CARGO_BUILD_JOBS=1 OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1 PKG_CONFIG_ALL_STATIC=1 \
    RUSTY_V8_ARCHIVE=/build/context/native-v8-inputs/librusty_v8_release_x86_64-unknown-linux-musl.a.gz \
    RUSTY_V8_SRC_BINDING_PATH=/build/context/native-v8-inputs/src_binding_release_x86_64-unknown-linux-musl.rs \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_LTO=off \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 RUSTUP_TOOLCHAIN=1.95.0 \
    AWS_LC_SYS_NO_JITTER_ENTROPY=1 LIBCLANG_PATH=/usr/lib/llvm21/lib \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/usr/local/bin/stateport-musl-linker
RUN printf '%s\n' '#!/bin/sh' 'exec /usr/bin/cc "$@" -B/usr/bin -fuse-ld=lld -Wl,--threads=1' \
      > /usr/local/bin/stateport-musl-linker && chmod 0755 /usr/local/bin/stateport-musl-linker
RUN test -s "$RUSTY_V8_ARCHIVE" && test -s "$RUSTY_V8_SRC_BINDING_PATH" \
    && cargo build --locked --release --target x86_64-unknown-linux-musl --bin codex
RUN mkdir -p /out \
    && cp target/x86_64-unknown-linux-musl/release/codex /out/codex \
    && cp Cargo.lock /out/Cargo.lock \
    && cp ../consumer-context.json /out/consumer-context.json \
    && /out/codex --version | grep -Fx 'codex-cli 0.146.0+stateport.3' \
    && sha256sum /out/codex > /out/codex.sha256 \
    && cargo tree --locked --target x86_64-unknown-linux-musl --package codex-cli --edges normal > /out/runtime-dependencies.txt \
    && rustc --version --verbose > /out/rustc.txt \
    && ld.lld --version > /out/linker-version.txt
