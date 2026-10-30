"""Command-line interface entry point for PrivacyLens."""

import logging
import sys

from privacylens.logging_setup import setup_logging

logger = logging.getLogger(__name__)


def main() -> None:
    """Run the PrivacyLens command line tool."""
    setup_logging()
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "version":
            print("PrivacyLens v0.1.0")
            return
        elif cmd == "token":
            if "--copy" in sys.argv:
                from privacylens.api.auth import copy_token_to_clipboard

                copied = copy_token_to_clipboard()
                if copied:
                    print("Pairing token copied to clipboard successfully.")
                else:
                    print("Failed to copy pairing token to clipboard.")
            else:
                print("Usage: privacylens token --copy")
            return
    print("PrivacyLens CLI. Available commands: version, token --copy")


if __name__ == "__main__":
    main()
