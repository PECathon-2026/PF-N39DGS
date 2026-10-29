import http.server
import socketserver
import os

PORT = 8765
DIR = os.path.join(os.path.dirname(__file__), "pages")

if __name__ == "__main__":
    os.chdir(DIR)
    with socketserver.TCPServer(("", PORT), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving eval pages on http://localhost:{PORT}")
        httpd.serve_forever()
