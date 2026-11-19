#!/usr/bin/env python3
"""Serve a directory on 127.0.0.1 for the wordlist-download tests.

    static_server.py <dir> <portfile>     (writes the chosen port, serves until killed)
"""
import functools
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=sys.argv[1]))
with open(sys.argv[2], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
