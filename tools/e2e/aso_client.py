"""Tiny AutoSecOps operator client for the E2E harness (cookie session)."""
import json, sys
import requests


class Aso:
    def __init__(self, state_file):
        st = json.load(open(state_file))
        self.st = st
        self.B = st["api"]
        self.ws = st["workspace_id"]
        self.s = requests.Session()
        r = self.s.post(f"{self.B}/auth/login",
                        data={"username": st["operator"], "password": st["password"]})
        assert r.status_code == 204, r.text

    def url(self, path):
        return f"{self.B}/workspaces/{self.ws}{path}"

    def req(self, method, path, ok=(200, 201, 204), **kw):
        r = self.s.request(method, self.url(path), **kw)
        if r.status_code not in ok:
            sys.exit(f"{method} {path} -> {r.status_code} {r.text[:800]}")
        return r.json() if r.content else None

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.req("POST", path, json=body, **kw)


def pub_hex(pub_file):
    return json.load(open(pub_file))["public_hex"]
