from __future__ import annotations

import sys

from app.security import hostname_from_url, is_blocked_host


def main() -> int:
    if len(sys.argv) != 5:
        return 1

    egress_mode = sys.argv[1]
    allowlist = [item for item in sys.argv[2].split(",") if item]
    registry_host = sys.argv[3]
    host = hostname_from_url(sys.argv[4])
    if is_blocked_host(host, allowlist):
        return 1
    if egress_mode == "offline":
        return 1 if host not in allowlist else 0
    if egress_mode == "registry_only":
        allowed = set(allowlist)
        if registry_host:
            allowed.add(registry_host)
        return 0 if host in allowed else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
