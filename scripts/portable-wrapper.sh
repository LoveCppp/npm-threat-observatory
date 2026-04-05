#!/bin/bash
set -euo pipefail

cmd_name="$(basename "$0")"
real_cmd="$(command -v -- "${cmd_name}" || true)"
if [[ "${real_cmd}" == "/opt/npm-security-check/bin/${cmd_name}" || -z "${real_cmd}" ]]; then
  for candidate in /usr/bin/"${cmd_name}" /bin/"${cmd_name}"; do
    if [[ -x "${candidate}" ]]; then
      real_cmd="${candidate}"
      break
    fi
  done
fi

emit_event() {
  local details_json
  details_json="$(python3 -c 'import json, sys; print(json.dumps({"command": sys.argv[1], "argv": sys.argv[2]}))' "${cmd_name}" "${joined_args}")"
  python3 /opt/npm-security-check/scripts/portable_emit.py \
    "${PORTABLE_EVENT_URL}" \
    "${ANALYSIS_ID}" \
    "${PHASE:-unknown}" \
    "$1" \
    "$2" \
    "$3" \
    "${details_json}"
}

joined_args="$*"
allowlist="${ALLOWED_INTERNAL_HOSTS:-}"
egress_mode="${EGRESS_MODE:-offline}"
registry_host="${REGISTRY_HOST:-}"

enforce_network_policy() {
  if [[ "${PUBLIC_ONLY_EGRESS:-true}" != "true" ]]; then
    return 0
  fi

  python3 /opt/npm-security-check/scripts/portable_netguard.py \
    "${egress_mode}" \
    "${allowlist}" \
    "${registry_host}" \
    "$1"
}

case "${cmd_name}" in
  curl|wget)
    for arg in "$@"; do
      if [[ "${arg}" == http://* || "${arg}" == https://* ]]; then
        if ! enforce_network_policy "${arg}"; then
          emit_event "portable blocked network access" "high" \
            "${cmd_name} was blocked by ${egress_mode} egress policy: ${arg}"
          exit 126
        fi
      fi
    done
    emit_event "portable network command" "high" \
      "${cmd_name} invoked during ${PHASE:-unknown}: ${joined_args}"
    ;;
  chmod)
    if [[ "${joined_args}" == *"+x"* ]]; then
      emit_event "portable download and execute chain" "high" \
        "chmod +x observed during ${PHASE:-unknown}: ${joined_args}"
    fi
    ;;
  cat|cp|grep|sed)
    if [[ "${joined_args}" == *".npmrc"* || "${joined_args}" == *".ssh"* || "${joined_args}" == *".aws"* || "${joined_args}" == *".git-credentials"* || "${joined_args}" == *"gcloud"* ]]; then
      emit_event "portable sensitive credential access" "high" \
        "${cmd_name} touched a bait credential path during ${PHASE:-unknown}: ${joined_args}"
    fi
    ;;
esac

exec "${real_cmd}" "$@"
