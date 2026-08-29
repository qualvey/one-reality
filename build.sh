#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
LDFLAGS="-s -w -X RealityChecker/internal/version.Version=${VERSION} -X RealityChecker/internal/version.Commit=${COMMIT} -X RealityChecker/internal/version.BuildTime=${BUILD_TIME}"

mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}"/reality-checker*

build_target() {
  local os="$1"
  local arch="$2"
  local suffix=""
  local name="reality-checker-${os}-${arch}"
  if [[ "${os}" == "windows" ]]; then
    suffix=".exe"
  fi

  echo "Building ${os}/${arch}..."
  CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${DIST_DIR}/${name}${suffix}" "${ROOT_DIR}"
  (
    cd "${DIST_DIR}"
    if command -v zip >/dev/null 2>&1; then
      zip -q -j "${name}.zip" "${name}${suffix}"
    fi
  )
}

echo "Version: ${VERSION}"
echo "Commit: ${COMMIT}"
echo "Build time: ${BUILD_TIME}"

build_target linux amd64
build_target linux arm64
build_target windows amd64

echo "Build artifacts: ${DIST_DIR}"
ls -lh "${DIST_DIR}"
