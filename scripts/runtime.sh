#!/bin/bash
set -euo pipefail

source /opt/npm-security-check/scripts/portable-common.sh
prepare_portable_environment "runtime"
enable_portable_node_hook

mkdir -p /workspace/runtime
cd /workspace/runtime

cat > package.json <<EOF
{
  "name": "runtime-${ANALYSIS_ID}",
  "version": "1.0.0",
  "private": true
}
EOF

npm config set fund false
npm config set audit false
if [[ "${SOURCE_TYPE:-registry}" == "sample" ]]; then
  npm install "${SAMPLE_PATH}" --ignore-scripts=false --foreground-scripts --loglevel=error
elif [[ "${SOURCE_TYPE:-registry}" == "upload" ]]; then
  npm config set registry "${REGISTRY_URL}"
  npm install "${LOCAL_PACKAGE_PATH}" --ignore-scripts=false --foreground-scripts --loglevel=error
else
  npm config set registry "${REGISTRY_URL}"
  npm install "${PACKAGE_NAME}@${PACKAGE_VERSION}" --ignore-scripts=false --foreground-scripts --loglevel=error
fi

if [[ "${RUNTIME_MODE}" == "none" ]]; then
  exit 0
fi

cat > runtime-trigger.js <<EOF
const pkg = process.env.PACKAGE_NAME;
try {
  const mod = require(pkg);
  if (typeof mod === "function") {
    mod();
  }
} catch (error) {
  console.error("runtime trigger failed", error.message);
}
EOF

node runtime-trigger.js
