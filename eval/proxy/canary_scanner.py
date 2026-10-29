from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

try:
    from eval.canaries.registry import generate_registry

    _default_registry = generate_registry(42)
    _default_canaries = set(_default_registry.all_values())
except Exception:
    _default_canaries = set()

# Default dump file path for recording outbound proxy flows
DEFAULT_DUMP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures.json")


class CanaryScannerAddon:
    """mitmproxy addon that records outbound request payloads and searches for canaries.
    
    Invariant: Does not store raw sensitive canary values in persistent logs.
    """

    def __init__(self, canaries: Optional[Set[str]] = None, dump_path: Optional[str] = None):
        self.canaries: Set[str] = canaries if canaries is not None else set(_default_canaries)
        self.dump_path = dump_path or DEFAULT_DUMP_FILE
        self.recorded_count = 0
        self.leak_count = 0
        self.records: List[Dict[str, Any]] = []

    def set_canaries(self, canaries: Set[str]) -> None:
        self.canaries = set(canaries)

    def request(self, flow: Any) -> None:
        """Inspect outbound request before transmission."""
        url = flow.request.pretty_url
        method = flow.request.method
        body = flow.request.get_text() or ""

        # Search for canaries in URL and body
        hits = 0
        for c in self.canaries:
            if c in body or c in url:
                hits += 1

        self.recorded_count += 1
        if hits > 0:
            self.leak_count += hits

        record = {
            "index": self.recorded_count,
            "timestamp": time.time(),
            "method": method,
            "host": flow.request.host,
            "path": flow.request.path,
            "body_length": len(body),
            "canary_leak_count": hits,
            "leak_detected": hits > 0,
        }
        self.records.append(record)

        if self.dump_path:
            try:
                os.makedirs(os.path.dirname(self.dump_path), exist_ok=True)
                with open(self.dump_path, "w", encoding="utf-8") as f:
                    json.dump(self.records, f, indent=2)
            except Exception:
                pass


_active_proxy_proc: Optional[subprocess.Popen] = None


def start_proxy(port: int = 8080, dump_file: Optional[str] = None) -> Optional[subprocess.Popen]:
    """Launch mitmproxy in background as a recording proxy on specified port."""
    global _active_proxy_proc
    script_path = os.path.abspath(__file__).replace("\\", "/")
    cmd = [
        sys.executable,
        "-c",
        f"import sys; from mitmproxy.tools.main import mitmdump; sys.argv=['mitmdump', '-p', '{port}', '-s', r'{script_path}', '--set', 'block_global=false']; mitmdump()",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2.0)
        _active_proxy_proc = proc
        return proc
    except Exception:
        return None


def stop_proxy(proc: Optional[subprocess.Popen] = None) -> None:
    """Terminate the active recording proxy process."""
    global _active_proxy_proc
    target = proc or _active_proxy_proc
    if target:
        try:
            target.terminate()
            target.wait(timeout=3)
        except Exception:
            try:
                target.kill()
            except Exception:
                pass
    if target == _active_proxy_proc:
        _active_proxy_proc = None


# mitmproxy addon entrypoint when run via `mitmdump -s canary_scanner.py`
addons = [CanaryScannerAddon()]

__all__ = [
    "CanaryScannerAddon",
    "start_proxy",
    "stop_proxy",
    "DEFAULT_DUMP_FILE",
]
