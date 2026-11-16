"""The web app in a real browser (Chromium via Playwright). Skipped when Playwright isn't installed.

    pip install playwright && playwright install chromium     (CI does this)
"""

import os
import threading
from dataclasses import replace
from datetime import date

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

from agent_checkpoint.policy import AgentScope  # noqa: E402
from agent_checkpoint.server import ServerConfig, make_server  # noqa: E402
from agent_checkpoint.store import PurchaseOrder, Vendor  # noqa: E402
from agent_checkpoint.tenancy import Registry  # noqa: E402

PW = "correct-horse-staple-91"
XSS = '<img src=x onerror="window.__pwned=1">'


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    reg = Registry(str(tmp_path_factory.mktemp("home")))
    reg.create_org("acme", "Acme Corp")
    reg.save_policy("acme", replace(reg.policy("acme"), mode="enforce"))
    reg.add_agent("acme", "ap", AgentScope(("pay", "change_bank"), 100_000_00, 500_000_00, "Claude"))
    reg.add_user("acme", "admin@acme.com", "admin", PW)
    reg.add_user("acme", "audit@acme.com", "auditor", PW)
    gw = reg.gateway("acme")
    gw.org.store.upsert_vendor(Vendor("V1", XSS, "US000210000012345", ("v1.com",), date(2024, 1, 1), phone="+1 555 0100"))
    gw.org.store.upsert_po(PurchaseOrder("PO-1", "V1", 900_000_00))
    for i, amount in enumerate((12_000_00, 15_000_00)):
        gw.submit({"request_id": f"R{i}", "action": "pay", "vendor_id": "V1", "amount_cents": amount,
                   "invoice_number": f"I{i}", "po_number": "PO-1",
                   "evidence": [{"kind": "invoice", "ref": "i.pdf", "sender": "b@v1.com"}],
                   "instructed_by": {"source": "email", "identity": "b@v1.com"}}, agent_id="ap")
    gw.submit({"request_id": "B1", "action": "change_bank", "vendor_id": "V1", "bank_account": "US99887766554433",
               "evidence": [{"kind": "email", "ref": "m.eml", "sender": "ap@v1.com"}],
               "instructed_by": {"source": "email", "identity": "ap@v1.com"}}, agent_id="ap")
    srv = make_server(reg, "127.0.0.1", 0, ServerConfig(secure_cookies=False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", reg
    srv.shutdown()


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        exe = os.environ.get("CHROME_PATH") or ("/usr/bin/google-chrome" if os.path.exists("/usr/bin/google-chrome") else None)
        try:
            b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"no browser: {exc}")
        yield b
        b.close()


def sign_in(browser, base, email, viewport=None):
    ctx = browser.new_context(viewport=viewport or {"width": 1280, "height": 900})
    page = ctx.new_page()
    problems = []
    page.on("pageerror", lambda e: problems.append(str(e)))
    page.on("console", lambda m: problems.append(m.text) if "Content Security Policy" in m.text else None)
    page.goto(base + "/")
    page.fill("#email", email)
    page.fill("#password", PW)
    page.click("button[type=submit]")
    page.wait_for_selector(".slip")
    return page, problems


def test_approve_flow_and_no_script_injection(site, browser):
    base, reg = site
    page, problems = sign_in(browser, base, "admin@acme.com")
    assert page.locator(".slip").count() == 3
    assert page.locator(".slip-vendor").first.text_content() == XSS  # shown as text
    assert page.evaluate("window.__pwned") is None                    # never run
    slip = page.locator(".slip", has_text="$15,000.00")
    slip.locator("textarea").fill("Checked the PO.")
    slip.get_by_role("button", name="Approve payment").click()
    page.wait_for_selector("#toast:has-text('Payment approved')")
    sync_api.expect(page.locator(".slip")).to_have_count(2)  # (the CSP even blocks test-tool string eval)
    entries = reg.gateway("acme").org.ledger.entries("human_decision")
    assert entries[-1]["body"]["note"] == "Checked the PO."
    assert problems == []


def test_bank_change_needs_the_phone_call_box(site, browser):
    base, _ = site
    page, _ = sign_in(browser, base, "admin@acme.com")
    slip = page.locator(".slip", has_text="Bank change")
    approve = slip.get_by_role("button", name="Approve bank change")
    assert approve.is_disabled()
    slip.get_by_label("I called the vendor").check()
    assert approve.is_enabled()


def test_auditor_sees_but_cannot_decide(site, browser):
    base, _ = site
    page, _ = sign_in(browser, base, "audit@acme.com")
    assert page.get_by_role("button", name="Approve payment").count() == 0
    page.goto(base + "/#audit-log")
    page.wait_for_selector("text=Intact.")


def test_phone_layout_and_pages(site, browser):
    base, _ = site
    page, problems = sign_in(browser, base, "admin@acme.com", {"width": 375, "height": 740})
    for route in ("approvals", "overview", "activity", "audit-log", "vendors", "company-settings"):
        page.goto(f"{base}/#{route}")
        page.wait_for_selector("#main h1")
        assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), route
    assert problems == []
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_selector("text=You are signed out.")


def test_two_step_setup_and_sign_in_in_the_browser(site, browser):
    import time

    from agent_checkpoint import totp
    base, reg = site
    reg.add_user("acme", "twostep@acme.com", "approver", PW)
    page, problems = sign_in(browser, base, "twostep@acme.com")
    page.goto(base + "/#account")
    page.get_by_role("button", name="Set up two-step sign-in").click()
    page.wait_for_selector("img.qr")
    assert page.locator("img.qr").evaluate("img => img.naturalWidth > 100")  # the QR image rendered under the CSP
    key = page.locator(".key").text_content().replace(" ", "")
    page.fill("#setup-code", totp.code_at(key, int(time.time() // 30)))
    page.get_by_role("button", name="Turn on two-step sign-in").click()
    page.wait_for_selector(".codes li")
    assert page.locator(".codes li").count() == 10
    page.get_by_role("button", name="I've saved my recovery codes").click()
    page.wait_for_selector("text=On. 10 recovery codes left.")
    page.get_by_role("button", name="Sign out").click()
    page.wait_for_selector("text=You are signed out.")
    page.fill("#email", "twostep@acme.com")
    page.fill("#password", PW)
    page.click("button[type=submit]")
    page.wait_for_selector("#code")  # (this step found a keep-alive bug: sign-out left its body on the connection)
    page.fill("#code", totp.code_at(key, int(time.time() // 30) + 1))
    page.get_by_role("button", name="Continue").click()
    page.wait_for_selector(".slip")
    assert problems == []
