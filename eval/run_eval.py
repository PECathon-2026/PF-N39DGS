"""Evaluation runner comparing local detections against ground truth dataset."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_ground_truth(path: str | Path = "eval/ground_truth.json") -> dict[str, Any]:
    """Load ground truth JSON dataset."""
    ground_truth_path = Path(path)
    if not ground_truth_path.exists():
        raise FileNotFoundError(f"Ground truth not found at {ground_truth_path}")
    with open(ground_truth_path, encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    """Run evaluation benchmark comparing detector findings against ground truth."""
    gt = load_ground_truth()
    canaries = gt.get("canaries", [])
    pages = gt.get("pages", {})
    logger.info("Loaded ground truth with %d canaries across %d pages", len(canaries), len(pages))


if __name__ == "__main__":
    main()

