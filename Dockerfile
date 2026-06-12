# syntax=docker/dockerfile:1
#
# Multi-stage build for cpp-FuSa.
# Stage 1 compiles the cpfusa binary with CMake + Ninja.
# Stage 2 produces a minimal Alpine runtime image.
#
# Build:
#   docker build -t cpp-fusa .
#
# Run (mount your C++ project at /project):
#   docker run --rm -v "$(pwd)":/project cpp-fusa check
#   docker run --rm -v "$(pwd)":/project cpp-fusa lint
#   docker run --rm -v "$(pwd)":/project cpp-fusa trace --format json
#   docker run --rm -v "$(pwd)":/project cpp-fusa release

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    cmake ninja clang clang-dev g++ git zip \
    && ln -sf /usr/bin/clang   /usr/local/bin/cc \
    && ln -sf /usr/bin/clang++ /usr/local/bin/c++

WORKDIR /build

# Copy source tree
COPY . .

# FetchContent needs network access at configure time; the layer is cached on
# subsequent builds as long as CMakeLists.txt / cmake/ are unchanged.
RUN cmake -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_STANDARD=17 \
      -DCPFUSA_BUILD_TESTS=OFF \
      -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
      -G Ninja \
    && cmake --build build --parallel \
    && strip build/cpfusa

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# git for impact/provenance; zip for audit-pack; ca-certificates for TLS.
# libstdc++ is statically linked into the binary, so not needed at runtime.
RUN apk add --no-cache git zip ca-certificates

COPY --from=builder /build/build/cpfusa /usr/local/bin/cpfusa

# Default working directory is /project; mount your C++ project here.
WORKDIR /project

LABEL org.opencontainers.image.title="cpp-FuSa" \
      org.opencontainers.image.description="C++ functional safety toolkit" \
      org.opencontainers.image.source="https://github.com/SoundMatt/cpp-FuSa" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="0.12.0" \
      io.x-fusa.tool="cpp-FuSa" \
      io.x-fusa.language="cpp" \
      io.x-fusa.binary="cpfusa" \
      io.x-fusa.spec-version="1.9"

ENTRYPOINT ["cpfusa"]
CMD ["--help"]
