#!/bin/bash
# Multi-platform release builder for Venom v0.9.0-alpha
# Produces binaries for macOS (arm64 + x86_64), Linux (musl + glibc), Windows (MSVC)

set -e

VERSION="1.0.0"
CARGO_RELEASE_DIR="target/release"
RELEASE_DIR="releases/${VERSION}"
CHECKSUM_FILE="${RELEASE_DIR}/SHA256SUMS"

echo "🔨 Building VENOM v${VERSION} for multiple platforms..."

mkdir -p "${RELEASE_DIR}"

# Detect system
SYSTEM=$(uname -s)
ARCH=$(uname -m)

build_platform() {
    local target=$1
    local name=$2

    echo "📦 Building for ${name} (${target})..."

    rustup target add "${target}" 2>/dev/null || true
    cargo build --release --target "${target}" --quiet

    local binary_name="venom"
    if [[ "${target}" == *"windows"* ]]; then
        binary_name="venom.exe"
    fi

    local src_path="${CARGO_RELEASE_DIR}/${target}/release/${binary_name}"
    local dst_path="${RELEASE_DIR}/venom-${VERSION}-${target}"

    if [ -f "${src_path}" ]; then
        if [[ "${target}" == *"windows"* ]]; then
            cp "${src_path}" "${dst_path}.exe"
            echo "✅ ${name}: ${dst_path}.exe"
        else
            cp "${src_path}" "${dst_path}"
            chmod +x "${dst_path}"
            echo "✅ ${name}: ${dst_path}"
        fi
    else
        echo "⚠️  Binary not found at ${src_path}"
    fi
}

# Build for all platforms
build_platform "x86_64-unknown-linux-gnu" "Linux x86_64 (glibc)"
build_platform "x86_64-unknown-linux-musl" "Linux x86_64 (musl)"
build_platform "aarch64-unknown-linux-gnu" "Linux ARM64 (glibc)"
build_platform "aarch64-unknown-linux-musl" "Linux ARM64 (musl)"

# macOS builds (only on macOS)
if [[ "${SYSTEM}" == "Darwin" ]]; then
    build_platform "x86_64-apple-darwin" "macOS x86_64"
    build_platform "aarch64-apple-darwin" "macOS ARM64"
fi

# Windows build (cross-compile on non-Windows)
build_platform "x86_64-pc-windows-msvc" "Windows x86_64"

# Generate checksums
echo "📝 Generating checksums..."
cd "${RELEASE_DIR}"
sha256sum venom-* > SHA256SUMS
cat SHA256SUMS

echo "✅ Release build complete!"
echo "📁 Binaries in: ${RELEASE_DIR}/"
echo "📋 Checksums in: ${CHECKSUM_FILE}"
