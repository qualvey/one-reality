#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
APP_NAME="${APP_NAME:-reality-checker}"
VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
LDFLAGS="-s -w -X RealityChecker/internal/version.AppName=${APP_NAME} -X RealityChecker/internal/version.Version=${VERSION} -X RealityChecker/internal/version.Commit=${COMMIT} -X RealityChecker/internal/version.BuildTime=${BUILD_TIME}"

mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}"/reality-checker*

# 准备编译时内置资产（Country.mmdb）
ASSETS_DIR="${ROOT_DIR}/internal/data/assets"
mkdir -p "${ASSETS_DIR}"
MMDB_TARGET="${ASSETS_DIR}/Country.mmdb"

download_mmdb() {
  echo "Checking and preparing Country.mmdb for embedding..."
  local tmp_file="${MMDB_TARGET}.tmp"
  local urls=(
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
    "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"
  )

  local downloaded=false
  for url in "${urls[@]}"; do
    echo "Downloading ${url}..."
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL --connect-timeout 15 --retry 2 "${url}" -o "${tmp_file}"; then
        mv "${tmp_file}" "${MMDB_TARGET}"
        echo "Country.mmdb downloaded and updated successfully."
        downloaded=true
        break
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q --timeout=15 --tries=2 "${url}" -O "${tmp_file}"; then
        mv "${tmp_file}" "${MMDB_TARGET}"
        echo "Country.mmdb downloaded and updated successfully."
        downloaded=true
        break
      fi
    fi
  done
  rm -f "${tmp_file}"

  if [ "${downloaded}" = false ]; then
    if [ -f "${MMDB_TARGET}" ] && [ -s "${MMDB_TARGET}" ]; then
      echo "Warning: Download Country.mmdb failed, using existing embedded version at ${MMDB_TARGET}."
    elif [ -f "${ROOT_DIR}/data/Country.mmdb" ] && [ -s "${ROOT_DIR}/data/Country.mmdb" ]; then
      echo "Warning: Download Country.mmdb failed, copying local data/Country.mmdb to ${MMDB_TARGET}."
      cp "${ROOT_DIR}/data/Country.mmdb" "${MMDB_TARGET}"
    else
      echo "Error: Cannot find or download Country.mmdb for embedding."
      exit 1
    fi
  fi
}

download_mmdb

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
