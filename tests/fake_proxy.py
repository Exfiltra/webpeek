#!/usr/bin/env python3
"""Minimal forwarding HTTP proxy for the --proxy tests (plain http only).

    fake_proxy.py <portfile> <logfile>

Logs every absolute-URI request line it receives to <logfile>, forwards it
directly (never via an environment proxy) and relays the response unchanged,
redirects included. Serves until killed.
"""
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = sys.argv[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        with open(LOG, "a") as f:
            f.write(f"{self.command} {self.path}\n")
        req = urllib.request.Request(self.path, headers={
            k: v for k, v in self.headers.items() if k.lower() not in ("proxy-connection", "host")})
        try:
            resp = OPENER.open(req, timeout=10)
            status, headers, body = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, e.headers, (e.read() if e.fp else b"")
        except Exception as e:
            status, headers, body = 502, {}, str(e).encode()
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


srv = HTTPServer(("127.0.0.1", 0), Proxy)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
