"""Telling a human that an agent is waiting for them.

`WebhookNotifier` posts JSON to any URL: Slack incoming webhooks, ntfy.sh (phone push), Teams,
or your own service. The HTTP call is injectable so tests never touch the network, and a
failed notification never blocks or approves anything: the ticket just waits, then expires.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from collections.abc import Callable


class Notifier:
    def send(self, ticket_id: str, text: str, approvers: tuple[str, ...]) -> None:  # pragma: no cover
        raise NotImplementedError


class ConsoleNotifier(Notifier):
    def send(self, ticket_id, text, approvers):
        print(f"[notify {', '.join(approvers) or 'approvers'}] {text} (ticket {ticket_id})", file=sys.stderr)


class CollectingNotifier(Notifier):
    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    def send(self, ticket_id, text, approvers):
        self.sent.append((ticket_id, text))


def _post(url: str, body: bytes, headers: dict) -> None:  # pragma: no cover - network
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5):
        pass


class WebhookNotifier(Notifier):
    def __init__(self, url: str, approve_url: str = "", post: Callable = _post):
        self.url, self.approve_url, self.post = url, approve_url, post

    def send(self, ticket_id, text, approvers):
        link = f" {self.approve_url}/{ticket_id}" if self.approve_url else ""
        body = json.dumps({"text": text + link, "ticket_id": ticket_id}).encode()
        try:
            self.post(self.url, body, {"Content-Type": "application/json"})
        except Exception as exc:  # never let a notification failure change a decision
            print(f"notification failed for {ticket_id}: {exc}", file=sys.stderr)
