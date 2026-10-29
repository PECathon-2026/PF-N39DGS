"""Lightweight HTTP server serving synthetic test site pages on port 8765."""

import http.server
import logging
import socketserver
import sys
from functools import partial
from pathlib import Path

logger = logging.getLogger(__name__)

PORT = 8765
DIRECTORY = Path(__file__).parent.resolve()


def run_server(port: int = PORT) -> None:
    """Start local HTTP server serving test site files."""
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(DIRECTORY))

    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Serving test site at http://127.0.0.1:{port}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            httpd.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port_arg)
