#!/bin/bash

function usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options::
   -c ... do a clean build
   -t ... tag to use
EOF
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BAZEL_TARGET_DIR="${ROOT}/bazel-bin/src/envoy/authz"
DEBUG_IMAGE_NAME="quay.io/saurabh/dtp:latest"

CLEAN_BUILD=0
while getopts c arg; do
  case ${arg} in
     c) CLEAN_BUILD=1 ;;
     t) DEBUG_IMAGE_NAME="${OPTARG}";;
     *) usage "Invalid option: -${OPTARG}";;
  esac
done

if [ $CLEAN_BUILD -eq 1 ]; then
  rm -rf ${BAZEL_TARGET_DIR}
  bazel build -c dbg //src/envoy/authz:envoy
fi

cp ./tests/echo.py ${BAZEL_TARGET_DIR}/
cp -r ./certs/ ${BAZEL_TARGET_DIR}/
cp ./tests/envoy.json ${BAZEL_TARGET_DIR}/
cp ./tests/dikastes-client.sh ${BAZEL_TARGET_DIR}/
cp docker/Dockerfile.debug ${BAZEL_TARGET_DIR}/
docker build -f ${BAZEL_TARGET_DIR}/Dockerfile.debug -t "${DEBUG_IMAGE_NAME}" ${BAZEL_TARGET_DIR}
echo "Push ${DEBUG_IMAGE_NAME} to a registry now"

