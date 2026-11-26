"""An in-memory company for tests, demos and the simulation: same code paths, nothing on disk."""

from __future__ import annotations

import secrets

from .gateway import Gateway, Org, utcnow
from .intel import Intel
from .journal import Journal
from .ledger import Ledger
from .notify import CollectingNotifier
from .policy import Policy
from .rails import SandboxRail
from .receipts import Signer, Verifier
from .store import Store


def make_org(org_id: str = "acme", name: str = "Acme Manufacturing", policy: Policy | None = None,
             intel: Intel | None = None, clock=utcnow) -> Gateway:
    store = Store(":memory:", secrets.token_bytes(32))
    signer = Signer.generate(org_id)
    org = Org(org_id, name, store, Journal(Ledger(":memory:", secrets.token_bytes(32)), store), policy or Policy(), signer,
              SandboxRail(store, Verifier(signer.public_pem())), CollectingNotifier(), intel)
    return Gateway(org, clock=clock)


def make_intel() -> Intel:
    return Intel(":memory:", secrets.token_bytes(32))
