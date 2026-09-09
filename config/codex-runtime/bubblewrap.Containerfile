# Preparation only; not consumed by any StatePort release image.
FROM docker.io/library/rust:1.95.0-alpine3.23@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS build
RUN apk add --no-cache build-base=0.5-r3 linux-headers=6.16.12-r0 \
    meson=1.9.1-r0 samurai=1.2-r7 python3=3.12.14-r0 \
    libcap-dev=2.78-r0 libcap-static=2.78-r0 pkgconf=2.5.1-r0
WORKDIR /build
COPY config/codex-runtime/bubblewrap-build.json /build/source.json
RUN python3 -c 'import json,hashlib,urllib.request; d=json.load(open("source.json")); data=urllib.request.urlopen(d["sourceUrl"],timeout=60).read(); assert hashlib.sha256(data).hexdigest()==d["sourceSha256"]; open("bubblewrap-0.12.0.tar.xz","wb").write(data)'
RUN echo '9760d007363e3abba7c747489910f9f82d9fca53ba3bd3282e396fa3c97a3314  bubblewrap-0.12.0.tar.xz' | sha256sum -c - \
    && tar -xf bubblewrap-0.12.0.tar.xz \
    && meson setup output bubblewrap-0.12.0 --buildtype=release \
      --default-library=static -Dprefer_static=true -Dc_link_args=-static \
      -Dman=disabled -Dselinux=disabled -Dtests=false \
      -Dbash_completion=disabled -Dzsh_completion=disabled \
    && meson compile -C output -j 1 \
    && mkdir /out \
    && cp output/bwrap /out/bwrap \
    && test "$(/out/bwrap --version)" = 'bubblewrap 0.12.0' \
    && readelf -l /out/bwrap > /out/elf-program-headers.txt \
    && ! grep -q INTERP /out/elf-program-headers.txt \
    && grep -q 'DYN (Position-Independent Executable file)' /out/elf-program-headers.txt \
    && cp bubblewrap-0.12.0/COPYING bubblewrap-0.12.0/LICENSE /out/ \
    && cp bubblewrap-0.12.0.tar.xz source.json /out/ \
    && apk info -vv > /out/build-packages.txt \
    && sha256sum /out/bwrap > /out/bwrap.sha256
FROM scratch
COPY --from=build /out/ /
