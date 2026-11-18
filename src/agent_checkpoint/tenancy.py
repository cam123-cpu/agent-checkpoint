"""Companies, keys, and where everything lives on disk.

    <home>/
      keys.json                 sha256(key) → {org, kind: agent|approver, name}. Keys are never stored.
      web.db, web.key           people who sign in to the web app (two-step secrets encrypted with web.key),
                                their sessions and sign-in limits
      network/intel.db, intel.key   the shared fraud network
      orgs/<org_id>/
        policy.json             the company's rules (edit this)
        notify.json             optional: {"webhook_url": "...", "approve_url": "..."}
        books.db                vendors, POs, payments, tickets, transfers
        ledger.db               the tamper-evident log
        ledger.key, data.key, signing.pem   secrets, mode 600

Every company is its own folder and its own databases, so no query can cross companies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from dataclasses import replace

from .accounts import Accounts, User
from .gateway import Gateway, Org
from .intel import Intel
from .ledger import Ledger
from .notify import ConsoleNotifier, WebhookNotifier
from .policy import AgentScope, Policy
from .rails import SandboxRail
from .receipts import Signer, Verifier
from .store import Store

_ORG = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _write_secret(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _copy_secret(src: str, dest: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    _write_secret(dest, data)
    os.remove(src)


class Registry:
    """`keys_home` (or the AGENT_CHECKPOINT_KEYS environment variable) puts every secret in another folder:
    a mounted secret, an encrypted volume, a different disk. A copy of the data folder alone then can't be
    decrypted or re-signed. Without it, secrets sit beside the databases, which `doctor` reports."""

    def __init__(self, home: str, keys_home: str | None = None):
        self.home = os.path.abspath(home)
        kh = keys_home if keys_home is not None else os.environ.get("AGENT_CHECKPOINT_KEYS", "")
        self.keys_home = os.path.abspath(kh) if kh else ""
        self._lock = threading.Lock()
        self._orgs: dict[str, Gateway] = {}
        self._intel: Intel | None = None
        self._accounts: Accounts | None = None

    # --- setup ----------------------------------------------------------------------

    def init(self) -> None:
        os.makedirs(os.path.join(self.home, "orgs"), exist_ok=True)
        os.makedirs(os.path.join(self.home, "network"), exist_ok=True)
        kp = self.secret_path("intel.key")
        if not os.path.exists(kp):
            _write_secret(kp, secrets.token_bytes(32))
        if not os.path.exists(self._keys_path):
            self._save_keys({})

    @property
    def _keys_path(self) -> str:
        return os.path.join(self.home, "keys.json")

    def _load_keys(self) -> dict:
        with open(self._keys_path) as f:
            return json.load(f)

    def _save_keys(self, keys: dict) -> None:
        tmp = self._keys_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(keys, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._keys_path)

    def secret_path(self, name: str, org_id: str = "") -> str:
        """Where a secret lives. Separate keys folder if configured (falling back to an existing copy beside
        the data, from before it was configured); otherwise beside the data."""
        beside = (os.path.join(self.org_dir(org_id), name) if org_id
                  else os.path.join(self.home, "network", name) if name == "intel.key" else os.path.join(self.home, name))
        if not self.keys_home:
            return beside
        apart = os.path.join(self.keys_home, org_id or "_", name)
        if os.path.exists(apart) or not os.path.exists(beside):
            os.makedirs(os.path.dirname(apart), mode=0o700, exist_ok=True)
            return apart
        return beside

    def secrets_beside_data(self) -> list[str]:
        """Secrets that sit in the data folder: a backup or copy of it carries what's needed to read it."""
        found = []
        for root, _dirs, files in os.walk(self.home):
            found += [os.path.join(root, f) for f in files if f.endswith(".key") or f == "signing.pem"]
        return sorted(found)

    def move_secrets(self) -> list[str]:
        """Move every secret into keys_home. Run once after setting AGENT_CHECKPOINT_KEYS."""
        if not self.keys_home:
            raise ValueError("set AGENT_CHECKPOINT_KEYS (or --keys) to a folder outside the data folder first")
        if os.path.commonpath([self.keys_home, self.home]) == self.home:
            raise ValueError("the keys folder must be outside the data folder")
        moved = []
        for path in self.secrets_beside_data():
            rel = os.path.relpath(path, self.home).split(os.sep)
            org = rel[1] if rel[0] == "orgs" else ""
            dest = os.path.join(self.keys_home, org or "_", rel[-1])
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            if os.path.exists(dest):
                raise ValueError(f"{dest} already exists; not overwriting a key")
            os.replace(path, dest) if os.stat(path).st_dev == os.stat(os.path.dirname(dest)).st_dev else _copy_secret(path, dest)
            moved.append(dest)
        return moved

    def org_dir(self, org_id: str) -> str:
        if not _ORG.match(org_id):
            raise ValueError("org id: lowercase letters, digits and dashes")
        return os.path.join(self.home, "orgs", org_id)

    def create_org(self, org_id: str, name: str, policy: Policy | None = None) -> None:
        self.init()
        d = self.org_dir(org_id)
        os.makedirs(d, exist_ok=False)
        with open(os.path.join(d, "policy.json"), "w") as f:
            f.write((policy or Policy()).to_json())
        with open(os.path.join(d, "org.json"), "w") as f:
            json.dump({"org_id": org_id, "name": name}, f)
        _write_secret(self.secret_path("ledger.key", org_id), secrets.token_bytes(32))
        _write_secret(self.secret_path("data.key", org_id), secrets.token_bytes(32))
        Signer.generate(org_id).save(self.secret_path("signing.pem", org_id))

    def save_policy(self, org_id: str, policy: Policy) -> None:
        path = os.path.join(self.org_dir(org_id), "policy.json")
        with open(path + ".tmp", "w") as f:
            f.write(policy.to_json())
        os.replace(path + ".tmp", path)
        with self._lock:
            gw = self._orgs.get(org_id)
            if gw:
                gw.org.policy = policy

    def policy(self, org_id: str) -> Policy:
        with open(os.path.join(self.org_dir(org_id), "policy.json")) as f:
            return Policy.from_json(f.read())

    def _new_key(self, prefix: str, org_id: str, kind: str, name: str) -> str:
        key = f"{prefix}_{org_id}_{secrets.token_urlsafe(32)}"
        with self._lock:
            keys = self._load_keys()
            keys[_hash(key)] = {"org": org_id, "kind": kind, "name": name}
            self._save_keys(keys)
        return key

    def add_agent(self, org_id: str, agent_id: str, scope: AgentScope) -> str:
        p = self.policy(org_id)
        self.save_policy(org_id, replace(p, agents={**p.agents, agent_id: scope}))
        return self._new_key("ack", org_id, "agent", agent_id)

    def add_approver(self, org_id: str, email: str) -> str:
        p = self.policy(org_id)
        if email not in p.approvers:
            self.save_policy(org_id, replace(p, approvers=p.approvers + (email,)))
        return self._new_key("apk", org_id, "approver", email)

    def accounts(self) -> Accounts:
        if self._accounts is None:
            self.init()
            kp = self.secret_path("web.key")
            if not os.path.exists(kp):
                _write_secret(kp, secrets.token_bytes(32))
            with open(kp, "rb") as f:
                self._accounts = Accounts(os.path.join(self.home, "web.db"), f.read())
        return self._accounts

    def add_user(self, org_id: str, email: str, role: str, password: str) -> User:
        """A person who signs in to the web app. Admins and approvers can approve tickets."""
        if not os.path.isdir(self.org_dir(org_id)):
            raise KeyError(org_id)
        user = self.accounts().create_user(email, org_id, role, password)
        if role in ("admin", "approver"):
            p = self.policy(org_id)
            if user.email not in p.approvers:
                self.save_policy(org_id, replace(p, approvers=p.approvers + (user.email,)))
        return user

    def update_agent(self, org_id: str, agent_id: str, scope: AgentScope) -> None:
        p = self.policy(org_id)
        if agent_id not in p.agents:
            raise KeyError(agent_id)
        self.save_policy(org_id, replace(p, agents={**p.agents, agent_id: scope}))

    def remove_agent(self, org_id: str, agent_id: str) -> int:
        """Revoke every key the agent has and take it out of the policy. Returns the number of keys revoked."""
        with self._lock:
            keys = self._load_keys()
            gone = [h for h, who in keys.items() if who == {"org": org_id, "kind": "agent", "name": agent_id}]
            for h in gone:
                del keys[h]
            self._save_keys(keys)
        p = self.policy(org_id)
        self.save_policy(org_id, replace(p, agents={k: v for k, v in p.agents.items() if k != agent_id}))
        return len(gone)

    def agent_key_count(self, org_id: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for who in self._load_keys().values():
            if who["org"] == org_id and who["kind"] == "agent":
                out[who["name"]] = out.get(who["name"], 0) + 1
        return out

    def revoke(self, key: str) -> bool:
        with self._lock:
            keys = self._load_keys()
            found = keys.pop(_hash(key), None)
            self._save_keys(keys)
        return found is not None

    # --- use ------------------------------------------------------------------------

    def lookup(self, key: str) -> dict | None:
        """Constant-time match of a presented key against the stored hashes."""
        if not key or not os.path.exists(self._keys_path):
            return None
        h = _hash(key)
        found = None
        for stored, who in self._load_keys().items():
            if hmac.compare_digest(stored, h):
                found = who
        return found

    def intel(self) -> Intel:
        if self._intel is None:
            with open(self.secret_path("intel.key"), "rb") as f:
                self._intel = Intel(os.path.join(self.home, "network", "intel.db"), f.read())
        return self._intel

    def gateway(self, org_id: str) -> Gateway:
        with self._lock:
            if org_id in self._orgs:
                return self._orgs[org_id]
            d = self.org_dir(org_id)
            if not os.path.isdir(d):
                raise KeyError(org_id)
            with open(os.path.join(d, "org.json")) as f:
                meta = json.load(f)
            with open(self.secret_path("ledger.key", org_id), "rb") as f:
                ledger_key = f.read()
            with open(self.secret_path("data.key", org_id), "rb") as f:
                data_key = f.read()
            store = Store(os.path.join(d, "books.db"), data_key)
            signer = Signer.load(self.secret_path("signing.pem", org_id), org_id)
            notifier = ConsoleNotifier()
            np = os.path.join(d, "notify.json")
            if os.path.exists(np):
                with open(np) as f:
                    cfg = json.load(f)
                if cfg.get("webhook_url"):
                    notifier = WebhookNotifier(cfg["webhook_url"], cfg.get("approve_url", ""))
            with open(os.path.join(d, "policy.json")) as f:
                policy = Policy.from_json(f.read())
            org = Org(org_id, meta["name"], store, Ledger(os.path.join(d, "ledger.db"), ledger_key), policy,
                      signer, SandboxRail(store, Verifier(signer.public_pem())), notifier, None)
        org.intel = self.intel()
        gw = Gateway(org)
        with self._lock:
            self._orgs[org_id] = gw
        return gw
