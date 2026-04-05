#!/bin/bash

set -euo pipefail

prepare_portable_environment() {
  local phase="$1"
  export PHASE="${phase}"
  case ":${PATH}:" in
    *":/opt/npm-security-check/bin:"*) ;;
    *) export PATH="/opt/npm-security-check/bin:${PATH}" ;;
  esac
  export PORTABLE_EVENT_URL="${CALLBACK_BASE_URL}/internal/events"
  export HOME="/tmp/npm-security-home"
  export TMPDIR="/tmp/npm-security-check"
  export PYTHONPATH="/opt/npm-security-check:${PYTHONPATH:-}"

  mkdir -p "${HOME}/.ssh" "${HOME}/.aws" "${HOME}/.config/gcloud" "${TMPDIR}"
  printf '// bait npm token\n' > "${HOME}/.npmrc"
  printf 'fake ssh key\n' > "${HOME}/.ssh/id_rsa"
  printf '[default]\naws_access_key_id = FAKE\n' > "${HOME}/.aws/credentials"
  printf 'fake gcloud\n' > "${HOME}/.config/gcloud/application_default_credentials.json"
}

enable_portable_node_hook() {
  local portable_hook="--require=/opt/npm-security-check/scripts/portable-hook.js"
  case " ${NODE_OPTIONS:-} " in
    *" ${portable_hook} "*) ;;
    *) export NODE_OPTIONS="${portable_hook}${NODE_OPTIONS:+ ${NODE_OPTIONS}}" ;;
  esac
}
