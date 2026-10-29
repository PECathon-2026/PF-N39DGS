from __future__ import annotations

from typing import List

from core.detect.regex_layer import Finding


def fuse(findings: List[Finding]) -> List[Finding]:
    # favour recall: keep all, dedup exact (category, location)
    seen = set()
    out = []
    for f in findings:
        key = (f.category, str(f.location), f.layer)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
