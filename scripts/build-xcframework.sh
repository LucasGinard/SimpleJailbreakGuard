#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT_PATH="${PROJECT_DIR}/SDKSimpleJailbreakGuard.xcodeproj"
SCHEME="SDKSimpleJailbreakGuard"
FRAMEWORK_NAME="SDKSimpleJailbreakGuard"
BUILD_DIR="${PROJECT_DIR}/build"
DERIVED_DATA_DIR="${BUILD_DIR}/DerivedData"
IOS_ARCHIVE="${BUILD_DIR}/archives/${FRAMEWORK_NAME}-iOS.xcarchive"
SIMULATOR_ARCHIVE="${BUILD_DIR}/archives/${FRAMEWORK_NAME}-iOS-Simulator.xcarchive"
OUTPUT="${BUILD_DIR}/${FRAMEWORK_NAME}.xcframework"

rm -rf "${IOS_ARCHIVE}" "${SIMULATOR_ARCHIVE}" "${OUTPUT}" "${DERIVED_DATA_DIR}"
mkdir -p "${BUILD_DIR}/archives"

xcodebuild archive -quiet \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -archivePath "${IOS_ARCHIVE}" \
  -derivedDataPath "${DERIVED_DATA_DIR}" \
  CODE_SIGNING_ALLOWED=NO \
  SKIP_INSTALL=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES

xcodebuild archive -quiet \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -configuration Release \
  -destination "generic/platform=iOS Simulator" \
  -archivePath "${SIMULATOR_ARCHIVE}" \
  -derivedDataPath "${DERIVED_DATA_DIR}" \
  'ARCHS=arm64 x86_64' \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  SKIP_INSTALL=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES

IOS_FRAMEWORK="${IOS_ARCHIVE}/Products/Library/Frameworks/${FRAMEWORK_NAME}.framework"
SIMULATOR_FRAMEWORK="${SIMULATOR_ARCHIVE}/Products/Library/Frameworks/${FRAMEWORK_NAME}.framework"
IOS_BINARY="${IOS_FRAMEWORK}/${FRAMEWORK_NAME}"
SIMULATOR_BINARY="${SIMULATOR_FRAMEWORK}/${FRAMEWORK_NAME}"

require_architecture() {
  local binary="$1"
  local architecture="$2"
  local architectures
  architectures="$(lipo -archs "${binary}")"
  if [[ " ${architectures} " != *" ${architecture} "* ]]; then
    echo "Error: ${binary} no contiene la arquitectura ${architecture}." >&2
    exit 1
  fi
}

require_architecture "${IOS_BINARY}" "arm64"
require_architecture "${SIMULATOR_BINARY}" "arm64"
require_architecture "${SIMULATOR_BINARY}" "x86_64"

CREATE_ARGUMENTS=(
  xcodebuild -create-xcframework
  -framework "${IOS_FRAMEWORK}"
)

IOS_DSYM="${IOS_ARCHIVE}/dSYMs/${FRAMEWORK_NAME}.framework.dSYM"
SIMULATOR_DSYM="${SIMULATOR_ARCHIVE}/dSYMs/${FRAMEWORK_NAME}.framework.dSYM"
if [[ -d "${IOS_DSYM}" ]]; then
  CREATE_ARGUMENTS+=(-debug-symbols "${IOS_DSYM}")
fi
CREATE_ARGUMENTS+=(-framework "${SIMULATOR_FRAMEWORK}")
if [[ -d "${SIMULATOR_DSYM}" ]]; then
  CREATE_ARGUMENTS+=(-debug-symbols "${SIMULATOR_DSYM}")
fi
CREATE_ARGUMENTS+=(-output "${OUTPUT}")

"${CREATE_ARGUMENTS[@]}"

echo "XCFramework generado en: ${OUTPUT}"
