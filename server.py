#!/usr/bin/env python3

import os
from http.server import CGIHTTPRequestHandler, HTTPServer


class PasswordRequestHandler(CGIHTTPRequestHandler):
    """Serve static assets and run password.py as a CGI endpoint."""

    def is_cgi(self):
        if self.path == "/password.py":
            # Serve password.py from the repository root
            self.cgi_info = ("", "password.py")
            return True
        return super().is_cgi()


def main():
    port = int(os.environ.get("PORT", "8000"))
    bind = os.environ.get("BIND", "0.0.0.0")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    server = HTTPServer((bind, port), PasswordRequestHandler)
    print(f"Serving on {bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
