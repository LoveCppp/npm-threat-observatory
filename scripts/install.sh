#!/bin/bash
set -euo pipefail

source /opt/npm-security-check/scripts/portable-common.sh
prepare_portable_environment "install"
enable_portable_node_hook

mkdir -p /workspace/install
cd /workspace/install

cat > package.json <<EOF
{
  "name": "analysis-${ANALYSIS_ID}",
  "version": "1.0.0",
  "private": true
}
EOF

npm config set fund false
npm config set audit false

if [[ "${SOURCE_TYPE:-registry}" == "sample" ]]; then
  npm install "${SAMPLE_PATH}" --ignore-scripts=false --foreground-scripts --loglevel=verbose
elif [[ "${SOURCE_TYPE:-registry}" == "upload" ]]; then
  npm config set registry "${REGISTRY_URL}"
  npm install "${LOCAL_PACKAGE_PATH}" --ignore-scripts=false --foreground-scripts --loglevel=verbose
else
  npm config set registry "${REGISTRY_URL}"
  npm install "${PACKAGE_NAME}@${PACKAGE_VERSION}" --ignore-scripts=false --foreground-scripts --loglevel=verbose
fi
