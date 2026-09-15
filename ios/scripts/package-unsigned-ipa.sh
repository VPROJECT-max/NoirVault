#!/bin/bash
set -euo pipefail

APP_PATH="$1"
mkdir -p "$(dirname "$2")"
OUTPUT_PATH="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
STAGING_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIRECTORY}"' EXIT

mkdir -p "${STAGING_DIRECTORY}/Payload"
cp -R "${APP_PATH}" "${STAGING_DIRECTORY}/Payload/NoirVault.app"
(cd "${STAGING_DIRECTORY}" && /usr/bin/zip -qry "${OUTPUT_PATH}" Payload)
/usr/bin/shasum -a 256 "${OUTPUT_PATH}" > "${OUTPUT_PATH}.sha256"
