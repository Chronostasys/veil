#!/usr/bin/env bash
# Build libveilcore.so for HarmonyOS NEXT (arm64) and stage it for the HAP.
#
# Requirement: DevEco Studio (OpenHarmony NDK + clang). Override DEVECO_HOME if
# your install lives elsewhere.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVECO_HOME="${DEVECO_HOME:-/Applications/DevEco-Studio.app/Contents}"
NDK="$DEVECO_HOME/sdk/default/openharmony/native"
# OpenHarmony Go fork: standard Go emits *initial-exec* TLS for its runtime
# (runtime.tls_g), and HarmonyOS's musl refuses to dlopen a library that
# contains such a relocation:
#   "Error relocating libveil.so: initial-exec TLS resolves to dynamic
#    definition"
# The OpenHarmony port targets GOOS=openharmony with TLSDESC (global-dynamic),
# which musl accepts in a dlopen()ed module.
OHOS_GO="${OHOS_GO:-$HOME/ohos-go/star4277-ohos-go-19667c7/bin/go}"

if [[ ! -d "$NDK" ]]; then
  echo "OpenHarmony NDK not found at $NDK" >&2
  exit 1
fi

if [[ ! -x "$OHOS_GO" ]]; then
  echo "OpenHarmony Go toolchain not found at $OHOS_GO" >&2
  echo "Build it from https://github.com/star4277/ohos-go (tag v1.26.5-beta1):" >&2
  echo "  cd <fork>/src && GOROOT_BOOTSTRAP=\$(which go) bash ./make.bash" >&2
  exit 1
fi

export GOTOOLCHAIN=local
export GOOS=openharmony
export GOARCH=arm64
export CGO_ENABLED=1
export CC="$NDK/llvm/bin/aarch64-unknown-linux-ohos-clang"
export CXX="$NDK/llvm/bin/aarch64-unknown-linux-ohos-clang++"
export CGO_CFLAGS="--target=aarch64-linux-ohos --sysroot=$NDK/sysroot -O2 -ftls-model=global-dynamic"
export CGO_LDFLAGS="--target=aarch64-linux-ohos --sysroot=$NDK/sysroot"

LIB_DIR="$ROOT/entry/libs/arm64-v8a"
CPP_LIB_DIR="$ROOT/entry/src/main/cpp/libs/arm64-v8a"
mkdir -p "$LIB_DIR" "$CPP_LIB_DIR"

cd "$ROOT/core"
STAMP="$(date +%m%d-%H%M)"
LDFLAGS="-s -w -X veil/internal/version.Build=$STAMP -X veil/internal/version.Commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"

# c-archive, then statically linked into the NAPI shim (libveil.so).
#
# A c-shared Go library cannot be dlopen()ed on HarmonyOS: the Go runtime uses
# initial-exec TLS, and the loader rejects it with
#   "initial-exec TLS resolves to dynamic definition in libveilcore.so"
# Linking the archive into the shim puts the Go runtime inside libveil.so
# itself, where the TLS relocation is resolved at link time.
"$OHOS_GO" build -buildmode=c-archive -trimpath -ldflags "$LDFLAGS" \
  -o "$CPP_LIB_DIR/libveilcore.a" ./bridge

# Keep a c-shared build too: it is handy for host-side experiments and for
# downstream packaging that prefers a separate .so.
"$OHOS_GO" build -buildmode=c-shared -trimpath -ldflags "$LDFLAGS" \
  -o "$LIB_DIR/libveilcore.so" ./bridge

rm -f "$LIB_DIR/libveilcore.h" "$CPP_LIB_DIR/libveilcore.h"
ls -lh "$CPP_LIB_DIR/libveilcore.a" "$LIB_DIR/libveilcore.so"
file "$CPP_LIB_DIR/libveilcore.a"
