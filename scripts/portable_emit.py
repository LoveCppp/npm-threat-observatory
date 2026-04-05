from __future__ import annotations

import json
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def main() -> int:
    if len(sys.argv) != 8:
        return 1

    url, analysis_id, phase, rule, severity, output, details_raw = sys.argv[1:]
    try:
        details = json.loads(details_raw)
    except json.JSONDecodeError:
        details = {"raw": details_raw}

    details.setdefault("hostname", socket.gethostname())
    payload = {
        "analysis_id": analysis_id,
        "phase": phase,
        "rule": rule,
        "severity": severity,
        "output": output,
        "details": details,
        "event_time": datetime.now(timezone.utc).isoformat(),
        "source": "portable",
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2):
            return 0
    except (urllib.error.URLError, TimeoutError):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
