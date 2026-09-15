#!/bin/bash
set -euo pipefail

REPOSITORY_ROOT="${SRCROOT}/.."
if [[ "${PLATFORM_NAME}" == "iphonesimulator" ]]; then
  RUST_TARGET="aarch64-apple-ios-sim"
else
  RUST_TARGET="aarch64-apple-ios"
fi

cargo build --manifest-path "${REPOSITORY_ROOT}/Cargo.toml" --release --target "${RUST_TARGET}"
OUTPUT_DIRECTORY="${SRCROOT}/build/rust/${PLATFORM_NAME}"
mkdir -p "${OUTPUT_DIRECTORY}"
cp "${REPOSITORY_ROOT}/target/${RUST_TARGET}/release/libnoirvault.a" "${OUTPUT_DIRECTORY}/libnoirvault.a"
