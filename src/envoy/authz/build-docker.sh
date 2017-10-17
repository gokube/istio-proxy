#!/bin/bash

function usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options::
   -c ... do a clean build
   -p ... push to registry
   -r ... registry to use
   -t ... tag to use
EOF
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BAZEL_TARGET_DIR="${ROOT}/bazel-bin/src/envoy/authz"
REGISTRY_NAME="us.gcr.io/unique-caldron-775/istio-proxy"
TAG=$(git log --pretty="%h" -n 1)

CLEAN_BUILD=0
PUSH=0
while getopts "cpr:t:h" arg; do
  case ${arg} in
     c) CLEAN_BUILD=1 ;;
     p) PUSH=1 ;;
     r) REGISTRY_NAME="${OPTARG}";;
     t) TAG="${OPTARG}";;
     h) usage ;;
     *) usage "Invalid option: -${OPTARG}";;
  esac
done

IMAGE_NAME="${REGISTRY_NAME}/dtp:${TAG}"
echo "${IMAGE_NAME}"

if [ $CLEAN_BUILD -eq 1 ]; then
  rm -rf ${BAZEL_TARGET_DIR}
  bazel build -c dbg //src/envoy/authz:envoy
fi

cp ./tests/echo.py ${BAZEL_TARGET_DIR}/
cp -r ./certs/ ${BAZEL_TARGET_DIR}/
cp ./tests/envoy.json ${BAZEL_TARGET_DIR}/
cp ./tests/dikastes-client.sh ${BAZEL_TARGET_DIR}/
cp docker/Dockerfile.debug ${BAZEL_TARGET_DIR}/
docker build -f ${BAZEL_TARGET_DIR}/Dockerfile.debug -t "${IMAGE_NAME}" ${BAZEL_TARGET_DIR}
if [ $PUSH -eq 1 ]; then
  docker push ${IMAGE_NAME}
else 
  echo "Push ${IMAGE_NAME} to a registry now"
fi
