#!/usr/bin/env python3
"""Simple HTTP file server with CORS for browser file injection."""
import http.server
import os
import sys
import urllib.parse

PORT = 8766
SERVE_DIR = os.path.expanduser("~/Downloads")

class CORSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

if __name__ == "__main__":
    with http.server.HTTPServer(("127.0.0.1", PORT), CORSHandler) as httpd:
        print(f"Serving {SERVE_DIR} on http://127.0.0.1:{PORT}")
        httpd.serve_forever()
