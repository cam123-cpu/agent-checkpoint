"""HTTP API. One front door for every agent, whoever built it.

Agents (agent key):
    POST /v1/actions                    submit an action → decision
    GET  /v1/actions/<request_id>       current status (only your own requests)
    GET  /v1/vendors?q=                 vendor lookup (ids, names, last 4 digits only)
Approvers (approver key, scoped to their company):
    GET  /v1/tickets                    open tickets
    POST /v1/tickets/<id>               {"approve": bool, "note", "callback_verified", "fraud"}
    POST /v1/fraud-reports              {"request_id"}: report a blocked action to the network
    GET  /v1/report[?since=&until=]     shadow-mode report
    GET  /v1/ledger/verify              recompute the chain; GET /v1/ledger/head to publish
Anyone:
    GET  /v1/public-key                 the company's receipt-verification key (?org=)
    GET  /health

Standard library only. Put it behind TLS (Caddy, a load balancer) in any real deployment.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .gateway import CheckpointError
from .report import shadow_report
from .tenancy import Registry

MAX_BODY = 256 * 1024


def make_server(registry: Registry, host: str = "127.0.0.1", port: int = 8077) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "agent-checkpoint"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _send(self, status: int, body) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _who(self, kind: str) -> dict:
            auth = self.headers.get("Authorization", "")
            who = registry.lookup(auth[7:] if auth.startswith("Bearer ") else "")
            if who is None or who["kind"] != kind:
                raise CheckpointError(401, f"{kind} key required")
            return who

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError as exc:
                raise CheckpointError(400, "bad Content-Length") from exc
            if length > MAX_BODY:
                raise CheckpointError(413, "body too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError as exc:
                raise CheckpointError(400, "body is not JSON") from exc
            if not isinstance(body, dict):
                raise CheckpointError(400, "body must be a JSON object")
            return body

        def _route(self, method: str):
            url = urlparse(self.path)
            path, query = url.path.rstrip("/"), parse_qs(url.query)
            if method == "GET" and path == "/health":
                return 200, {"ok": True}
            if method == "GET" and path == "/v1/public-key":
                org = (query.get("org") or [""])[0]
                try:
                    return 200, {"org": org, "public_key": registry.gateway(org).org.signer.public_pem()}
                except (KeyError, ValueError) as exc:
                    raise CheckpointError(404, "no such company") from exc
            if path == "/v1/actions" and method == "POST":
                who = self._who("agent")
                return 200, registry.gateway(who["org"]).submit(self._body(), agent_id=who["name"]).to_dict()
            if path == "/v1/vendors" and method == "GET":
                from .mcp_server import _vendor_rows
                who = self._who("agent")
                q = (query.get("q") or [""])[0]
                if not q.strip():
                    raise CheckpointError(422, "q is required")
                return 200, {"vendors": _vendor_rows(registry.gateway(who["org"]).org.store.vendors(), q)}
            if path.startswith("/v1/actions/") and method == "GET":
                who = self._who("agent")
                return 200, registry.gateway(who["org"]).status(path.rsplit("/", 1)[-1], who["name"])

            who = self._who("approver")
            gw = registry.gateway(who["org"])
            if path == "/v1/tickets" and method == "GET":
                gw.expire()
                return 200, {"tickets": gw.org.store.tickets("open")}
            if path.startswith("/v1/tickets/") and method == "POST":
                b = self._body()
                if not isinstance(b.get("approve"), bool):
                    raise CheckpointError(422, "approve must be true or false")
                return 200, gw.resolve(path.rsplit("/", 1)[-1], who["name"], b["approve"], str(b.get("note", "")),
                                       callback_verified=b.get("callback_verified") is True,
                                       fraud=b.get("fraud") is True)
            if path == "/v1/fraud-reports" and method == "POST":
                gw.report_fraud(str(self._body().get("request_id", "")), who["name"])
                return 200, {"reported": True}
            if path == "/v1/report" and method == "GET":
                return 200, shadow_report(gw.org.ledger, (query.get("since") or [""])[0],
                                          (query.get("until") or [""])[0])
            if path == "/v1/ledger/verify" and method == "GET":
                ok, why = gw.org.ledger.verify()
                return 200, {"ok": ok, "detail": why, "head": gw.org.ledger.head()}
            if path == "/v1/ledger/head" and method == "GET":
                return 200, gw.org.ledger.head()
            raise CheckpointError(404, "not found")

        def _handle(self, method: str):
            try:
                status, body = self._route(method)
            except CheckpointError as exc:
                status, body = exc.status, {"error": str(exc)}
            except Exception:  # never leak internals
                status, body = 500, {"error": "internal error"}
            self._send(status, body)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

    return ThreadingHTTPServer((host, port), Handler)
