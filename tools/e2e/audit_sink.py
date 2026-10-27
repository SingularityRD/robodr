#!/usr/bin/env python3
"""Minimal audit-webhook receiver: appends "PATH<TAB>BODY" per POST.
usage: audit_sink.py PORT OUT_FILE"""
import http.server, sys

port, out = int(sys.argv[1]), sys.argv[2]


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        with open(out, "ab") as f:
            f.write(self.path.encode() + b"\t" + body.replace(b"\n", b" ") + b"\n")
        self.send_response(204); self.end_headers()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
