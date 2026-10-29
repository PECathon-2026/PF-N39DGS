"""Command-line interface entry point for PrivacyLens."""

import logging
import sys

from privacylens.logging_setup import setup_logging

logger = logging.getLogger(__name__)


def main() -> None:
    """Run the PrivacyLens command line tool."""
    setup_logging()
    logger.info("PrivacyLens CLI initialized.")
    if len(sys.argv) > 1 and sys.argv[1] == "version":
        logger.info("PrivacyLens v0.1.0")


if __name__ == "__main__":
    main()

