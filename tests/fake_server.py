#!/usr/bin/env python3
"""Local test target + fake Anthropic API for tests/run_tests.sh. 127.0.0.1 only.

  GET  /               200 with a deliberately flawed CSP + X-Frame-Options
  GET  /redirect-in    302 -> /            (same host: must be followed)
  GET  /redirect-out   302 -> evil.example.org (out of scope: must NOT be followed)
  POST /v1/messages    canned Anthropic Messages API response
  POST /v1beta/models/<m>:generateContent
                       canned Gemini response (with a thought part to ignore);
                       404 NOT_FOUND when <m> is "no-such-model"
  Every POST is recorded to $FAKE_AI_LOG so the test can inspect what was sent.

Usage: fake_server.py <portfile>   (writes the chosen port, serves until killed)
"""
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

FLAWED_CSP = ("default-src 'self'; script-src self 'unsafe-inline' https://*.cloudfront.net; "
              "connect-src 'self' wss://.bad.example; img-src *; img-src 'self'")

AI_REPLY = {
    "rule_review": [{"id": "CSP-UNSAFE-INLINE", "directive": "script-src",
                     "verdict": "agree", "comment": "No nonce or hash present."}],
    "additional_findings": [{"directive": "img-src", "value": "*", "issue": "test point",
                             "severity": "Low", "recommendation": "narrow it",
                             "confidence": "medium"}],
    "summary": "Fake model output for the test suite.",
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://evil.example.org/steal")
            self.end_headers()
            return
        if self.path == "/redirect-in":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        body = b"<html><head><title>t</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Security-Policy", FLAWED_CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply(self, code, obj):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        gemini = self.path.startswith("/v1beta/models/")
        key = (self.headers.get("x-goog-api-key") if gemini else self.headers.get("x-api-key")) or ""
        with open(os.environ["FAKE_AI_LOG"], "a") as f:
            f.write(json.dumps({
                "provider": "gemini" if gemini else "anthropic",
                "path": self.path,
                # Fingerprint, not the key: lets a test check WHICH key was sent.
                "key_fp": hashlib.sha256(key.encode()).hexdigest()[:12] if key else None,
                "has_api_key": bool(self.headers.get("x-goog-api-key") if gemini
                                    else self.headers.get("x-api-key")),
                "key_in_url": "key=" in self.path,
                "anthropic_version": self.headers.get("anthropic-version"),
                "body": req}) + "\n")

        if gemini:
            if "no-such-model" in self.path:
                self._reply(404, {"error": {"code": 404, "status": "NOT_FOUND",
                                            "message": "models/no-such-model is not found"}})
                return
            # Includes a thought-summary part, which the client must ignore.
            self._reply(200, {"candidates": [{
                "content": {"role": "model", "parts": [
                    {"text": "Considering the policy... {not json}", "thought": True},
                    {"text": json.dumps(dict(AI_REPLY, summary="Fake Gemini output."))}]},
                "finishReason": "STOP"}]})
            return
        # Wrapped in a code fence on purpose: models do this, the parser must cope.
        text = "```json\n" + json.dumps(AI_REPLY) + "\n```"
        out = json.dumps({"id": "msg_test", "type": "message", "role": "assistant",
                          "content": [{"type": "text", "text": text}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", 0), H)
    with open(sys.argv[1], "w") as f:
        f.write(str(srv.server_address[1]))
    srv.serve_forever()
