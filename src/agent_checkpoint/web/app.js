// Checkpoint web app. Plain JavaScript, no framework, no third-party code.
// Safety rules for this file (checked by tests/test_web_rules.py):
//  - Text from the server is only ever inserted with textContent, never as HTML.
//  - No inline event handlers, no eval, nothing loaded from another site.
//  - The session lives in an HttpOnly cookie this script can't read.
"use strict";

(function () {
  // ---------- data access: the real server, or the demo's in-browser copy ----------
  const httpBackend = {
    async call(method, path, body, raw) {
      const opts = { method, credentials: "same-origin", headers: { "X-Requested-With": "fetch" } };
      if (raw) {
        opts.headers["Content-Type"] = "text/csv";
        opts.body = raw;
      } else if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
      let res;
      try {
        res = await fetch("/api/web/" + path, opts);
      } catch (e) {
        throw new ApiError(0, "Can't reach the checkpoint. Check your connection and try again.");
      }
      if (res.headers.get("Content-Type") && res.headers.get("Content-Type").startsWith("text/csv")) {
        return await res.blob();
      }
      let data = {};
      try { data = await res.json(); } catch (e) { data = {}; }
      if (!res.ok) throw new ApiError(res.status, data.error || "The request failed.");
      return data;
    },
  };
  const backend = window.CHECKPOINT_BACKEND || httpBackend;

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }
  window.CheckpointApiError = ApiError;

  const api = {
    get: (p) => backend.call("GET", p),
    post: (p, b) => backend.call("POST", p, b === undefined ? {} : b),
    upload: (p, text) => backend.call("POST", p, undefined, text),
  };

  // ---------- small helpers ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v === null || v === undefined) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const money = (cents, currency) =>
    new Intl.NumberFormat("en-US", { style: "currency", currency: currency || "USD" }).format((cents || 0) / 100);
  const count = (n, one, many) => n + " " + (n === 1 ? one : many);
  const VERDICT = { block: "Blocked", pause: "Needs approval", go: "Allowed" };
  const STATUS = {
    done: "Done", observed: "Recorded only", waiting: "Waiting for approval", approved: "Approved",
    rejected: "Rejected", expired: "Expired", blocked: "Blocked",
  };
  const ACTION = { pay: "Payment", change_bank: "Bank change", refund: "Refund", edit_record: "Record edit" };
  const verdictTag = (v) => h("span", { class: "verdict " + v, text: VERDICT[v] || v });

  function untilText(iso) {
    const ms = new Date(iso).getTime() - Date.now();
    if (ms <= 0) return "Expired";
    const hours = Math.floor(ms / 3600000);
    if (hours >= 24) return "Expires in " + count(Math.floor(hours / 24), "day", "days");
    if (hours >= 1) return "Expires in " + count(hours, "hour", "hours");
    return "Expires in " + count(Math.max(1, Math.floor(ms / 60000)), "minute", "minutes");
  }

  function dateText(iso) {
    const d = new Date(iso.length === 10 ? iso + "T12:00:00" : iso);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  }

  let toastTimer = null;
  function toast(message) {
    let el = document.getElementById("toast");
    if (!el) {
      el = h("div", { id: "toast", class: "toast", role: "status", "aria-live": "polite" });
      document.body.append(el);
    }
    el.hidden = false;
    el.textContent = message;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3500);
  }

  function errorBox(err) {
    return h("p", { class: "notice error", role: "alert", text: err.message || String(err) });
  }

  // Single sign-on failures arrive as a code in the address. Only these fixed sentences are ever shown, so a
  // crafted link can't put someone else's words ("call this number") on the real sign-in page.
  const SSO_ERRORS = {
    not_configured: "Single sign-on isn't set up for this company.",
    expired: "That sign-in took too long or was already used. Start again.",
    provider: "The sign-in provider didn't complete the sign-in. Start again.",
    token: "The sign-in couldn't be verified. Start again, or ask an admin to check the SSO settings.",
    no_account: "Your company account isn't set up in Checkpoint yet. Ask an admin to add you.",
    domain: "That account isn't from your company's domain.",
    needs_mfa: "Your sign-in provider didn't confirm a second factor, which this account needs. Sign in with your password and authenticator code instead, or turn on MFA with your provider.",
  };

  // ---------- state and routing ----------
  const state = { me: null, waiting: 0 };
  const root = document.getElementById("app");
  let renderSeq = 0;

  const PAGES = {
    approvals: { title: "Approvals", render: renderApprovals },
    overview: { title: "Overview", render: renderOverview },
    "payment-run": { title: "Payment run", render: renderPaymentRun },
    activity: { title: "Activity", render: renderActivity },
    "audit-log": { title: "Audit log", render: renderAudit },
    vendors: { title: "Vendors", render: renderVendors },
    setup: { title: "Setup", render: renderSettings },
    account: { title: "Your account", render: renderAccount, hidden: true },
  };

  function currentPage() {
    // Plain #name links (they survive being shared); #/name also accepted.
    const name = (location.hash || "").replace(/^#\/?/, "").split("?")[0];
    return PAGES[name] ? name : "approvals";
  }

  async function start() {
    try {
      state.me = await api.get("me");
    } catch (e) {
      if (e.status === 401) return renderSignIn(SSO_ERRORS[new URLSearchParams(location.search).get("sso_error")]);
      root.replaceChildren(h("main", { class: "page" }, errorBox(e)));
      return;
    }
    if (state.me.setup_required) return renderSetupRequired();
    render();
  }

  async function render() {
    const seq = ++renderSeq;
    const page = currentPage();
    document.title = PAGES[page].title + " | Checkpoint";
    const main = h("main", { class: "page", id: "main" }, h("p", { class: "muted", text: "Loading" }));
    root.replaceChildren(shell(page), main);
    try {
      const content = await PAGES[page].render();
      if (seq !== renderSeq) return; // a newer page was opened meanwhile
      main.replaceChildren(...[].concat(content).flat().filter((x) => x !== null && x !== undefined && x !== false));
    } catch (e) {
      if (seq !== renderSeq) return;
      if (e.status === 401) return renderSignIn("Your session ended. Sign in again.");
      main.replaceChildren(errorBox(e));
    }
  }

  function shell(active) {
    const me = state.me;
    const enforcing = me.mode === "enforce";
    const tabs = h("nav", { class: "tabs", "aria-label": "Sections" },
      Object.entries(PAGES).filter(([, p]) => !p.hidden).map(([key, p]) => h("a", {
        href: "#" + key, "aria-current": key === active ? "page" : false,
      }, p.title, key === "approvals" && state.waiting ? h("span", { class: "count", text: " (" + state.waiting + ")" }) : null)));
    return h("div", {},
      window.CHECKPOINT_DEMO_NOTE ? h("div", { class: "demo-banner" }, h("p", { text: window.CHECKPOINT_DEMO_NOTE })) : null,
      h("header", { class: "top" },
        h("div", { class: "top-inner" },
          h("span", { class: "brand", text: "Checkpoint" }),
          h("span", { class: "company", text: me.company }),
          h("div", { class: "who" },
            h("a", { class: "who-name", href: "#account", title: "Your account", text: me.email + " (" + me.role + ")" }),
            h("button", { class: "plain", type: "button", onclick: signOut }, "Sign out"))),
        h("div", { class: "mode " + me.mode },
          h("p", {},
            h("strong", { text: enforcing ? "Enforcing." : "Watching only." }),
            enforcing ? " Agents wait for the decisions below. Nothing they ask for happens until the checks pass or a person approves."
              : " Agents are not blocked yet. The checkpoint records what it would have stopped, so you can review it before turning enforcement on.")),
        tabs));
  }

  async function signOut() {
    try { await api.post("logout"); } catch (e) { /* signed out either way */ }
    state.me = null;
    renderSignIn("You are signed out.");
  }

  // ---------- sign in ----------
  function renderSignIn(message) {
    document.title = "Sign in | Checkpoint";
    const err = h("p", { class: "notice error", role: "alert", hidden: true });
    const email = h("input", { type: "email", id: "email", name: "email", autocomplete: "username", required: true });
    const password = h("input", { type: "password", id: "password", name: "password", autocomplete: "current-password",
      required: true, minlength: "12" });
    const honeypot = h("input", { type: "text", id: "website", name: "website", tabindex: "-1", autocomplete: "off" });
    const submit = h("button", { type: "submit" }, "Sign in");
    const form = h("form", { novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      err.hidden = true;
      if (!email.value || !password.value) {
        err.textContent = "Enter your email and password.";
        err.hidden = false;
        return;
      }
      submit.disabled = true;
      submit.textContent = "Signing in";
      try {
        const out = await api.post("login", { email: email.value, password: password.value, website: honeypot.value });
        password.value = "";
        if (out.two_step_required) return renderCodeStep(out.pending);
        if (!PAGES[currentPage()] || currentPage() === "account") location.hash = "#approvals";
        await start();
      } catch (e) {
        err.textContent = e.message;
        err.hidden = false;
        submit.disabled = false;
        submit.textContent = "Sign in";
      }
    } },
      h("div", { class: "field" }, h("label", { for: "email", text: "Email" }), email),
      h("div", { class: "field" }, h("label", { for: "password", text: "Password" }), password),
      h("div", { class: "hp", "aria-hidden": "true" }, h("label", { for: "website", text: "Leave this empty" }), honeypot),
      err, submit);
    const sso = h("div", { hidden: true });
    root.replaceChildren(h("main", { class: "signin" },
      h("h1", { text: "Checkpoint" }),
      h("p", { class: "muted", text: "Review and approve what your AI agents want to do with your company's money." }),
      message ? h("p", { class: "notice", role: "status", text: message }) : null,
      h("div", { class: "panel" }, sso, form)));
    email.focus();
    // A company's sign-in link carries ?org=<id>; if that company uses single sign-on, offer it first.
    const org = new URLSearchParams(location.search).get("org");
    if (org && /^[a-z0-9-]{2,41}$/.test(org)) {
      api.get("sso?org=" + encodeURIComponent(org)).then((r) => {
        if (!r.enabled) return;
        const go = h("button", { type: "button" }, "Sign in with " + r.label);
        go.addEventListener("click", () => { location.assign("/auth/sso/start?org=" + encodeURIComponent(org)); });
        sso.replaceChildren(go, h("p", { class: "small muted divider", text: "Or sign in with your email and password" }));
        sso.hidden = false;
      }).catch(() => {});
    }
  }

  function renderCodeStep(pending) {
    let recovery = false;
    const err = h("p", { class: "notice error", role: "alert", hidden: true });
    const label = h("label", { for: "code", text: "6-digit code from your authenticator app" });
    const code = h("input", { type: "text", id: "code", name: "code", inputmode: "numeric", autocomplete: "one-time-code",
      maxlength: "20", required: true });
    const submit = h("button", { type: "submit" }, "Continue");
    const swap = h("button", { type: "button", class: "plain" }, "Use a recovery code instead");
    swap.addEventListener("click", () => {
      recovery = !recovery;
      label.textContent = recovery ? "Recovery code (each works once)" : "6-digit code from your authenticator app";
      code.setAttribute("inputmode", recovery ? "text" : "numeric");
      swap.textContent = recovery ? "Use a code from the app instead" : "Use a recovery code instead";
      code.value = "";
      code.focus();
    });
    const form = h("form", { novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      err.hidden = true;
      submit.disabled = true;
      try {
        await api.post("login/two-step", { pending, code: code.value.trim() });
        location.hash = "#approvals";
        await start();
      } catch (e) {
        err.textContent = e.message;
        err.hidden = false;
        submit.disabled = false;
        if (e.status === 401 && /expired/.test(e.message)) setTimeout(() => renderSignIn(e.message), 1200);
      }
    } }, h("div", { class: "field" }, label, code), err, submit, h("p", {}, swap));
    root.replaceChildren(h("main", { class: "signin" },
      h("h1", { text: "Two-step sign-in" }),
      h("p", { class: "muted", text: "Open your authenticator app and enter the current code for Checkpoint." }),
      h("div", { class: "panel" }, form)));
    code.focus();
  }

  // ---------- two-step set-up (account page, and forced set-up) ----------
  function twoStepSetup(onDone) {
    const box = h("div", {});
    const err = h("p", { class: "notice error", role: "alert", hidden: true });
    const begin = h("button", { type: "button" }, "Set up two-step sign-in");
    begin.addEventListener("click", async () => {
      begin.disabled = true;
      err.hidden = true;
      try {
        const s = await api.post("two-step/start");
        const code = h("input", { type: "text", id: "setup-code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7" });
        const confirm = h("button", { type: "submit" }, "Turn on two-step sign-in");
        const copyKey = h("button", { type: "button", class: "secondary" }, "Copy key");
        copyKey.addEventListener("click", () => copyText(s.key.replace(/ /g, ""), "Key copied"));
        const form = h("form", { novalidate: true, onsubmit: async (ev) => {
          ev.preventDefault();
          err.hidden = true;
          confirm.disabled = true;
          try {
            const out = await api.post("two-step/confirm", { code: code.value.trim() });
            box.replaceChildren(recoveryCodes(out.recovery_codes, onDone));
          } catch (e) {
            err.textContent = e.message;
            err.hidden = false;
            confirm.disabled = false;
          }
        } },
          h("ol", { class: "steps" },
            h("li", {}, h("p", { text: "Open an authenticator app on your phone (for example Google Authenticator, Microsoft Authenticator or 1Password) and scan this code." }),
              h("img", { class: "qr", src: s.qr, width: "220", height: "220", alt: "QR code for adding Checkpoint to an authenticator app" })),
            h("li", {}, h("p", { text: "Can't scan it? Choose to enter a setup key in the app, and type this key:" }),
              h("p", { class: "key", text: s.key }), copyKey),
            h("li", {}, h("label", { for: "setup-code", text: "Enter the 6-digit code the app shows" }), code)),
          err, confirm);
        box.replaceChildren(form);
        code.focus();
      } catch (e) {
        err.textContent = e.message;
        err.hidden = false;
        begin.disabled = false;
      }
    });
    box.append(begin, err);
    return box;
  }

  function recoveryCodes(codes, onDone) {
    const done = h("button", { type: "button" }, "I've saved my recovery codes");
    done.addEventListener("click", onDone);
    const copy = h("button", { type: "button", class: "secondary" }, "Copy codes");
    copy.addEventListener("click", () => copyText(codes.join("\n"), "Recovery codes copied"));
    return h("div", { class: "panel" },
      h("h2", { text: "Two-step sign-in is on" }),
      h("p", { text: "Save these recovery codes somewhere safe, like a password manager. If you lose your phone, each code lets you sign in once. They won't be shown again." }),
      h("ul", { class: "codes" }, codes.map((c) => h("li", { class: "code", text: c }))),
      h("div", { class: "row" }, done, copy));
  }

  async function copyText(text, message) {
    try {
      await navigator.clipboard.writeText(text);
      toast(message);
    } catch (e) {
      toast("Copying isn't allowed here. Select the text and copy it instead.");
    }
  }

  function renderSetupRequired() {
    document.title = "Set up two-step sign-in | Checkpoint";
    root.replaceChildren(h("main", { class: "signin" },
      h("h1", { text: "Set up two-step sign-in" }),
      h("p", { class: "muted", text: state.me.company + " requires a code from an authenticator app each time you sign in with a password. It takes about a minute." }),
      h("div", { class: "panel" }, twoStepSetup(async () => { location.hash = "#approvals"; await start(); })),
      h("p", {}, h("button", { type: "button", class: "plain", onclick: signOut }, "Sign out"))));
  }

  // ---------- your account ----------
  async function renderAccount() {
    const me = await api.get("me");
    state.me = me;
    let twoStep;
    if (!me.two_step) {
      twoStep = h("section", { class: "panel" }, h("h2", { text: "Two-step sign-in" }),
        h("p", { text: "Off. Turn it on so a stolen password alone can't be used to approve payments." }),
        twoStepSetup(() => render()));
    } else {
      const pw = h("input", { type: "password", id: "off-pw", autocomplete: "current-password" });
      const code = h("input", { type: "text", id: "off-code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "20" });
      const msg = h("p", { class: "notice error", role: "alert", hidden: true });
      const off = h("button", { type: "submit", class: "danger" }, "Turn off two-step sign-in");
      twoStep = h("section", { class: "panel" }, h("h2", { text: "Two-step sign-in" }),
        h("p", { text: "On. " + count(me.recovery_codes_left, "recovery code", "recovery codes") + " left." + (me.recovery_codes_left < 3 ? " Ask an admin to reset two-step sign-in if you run out." : "") }),
        me.role === "admin" ? h("p", { class: "muted", text: "Admins always use two-step sign-in, so it stays on. If you lose your phone, another admin can reset it." }) :
        me.require_two_step ? h("p", { class: "muted", text: me.company + " requires two-step sign-in, so it stays on." }) :
          h("form", { novalidate: true, onsubmit: async (ev) => {
            ev.preventDefault();
            msg.hidden = true;
            try {
              await api.post("two-step/disable", { password: pw.value, code: code.value.trim() });
              renderSignIn("Two-step sign-in is off. Sign in again.");
            } catch (e) { msg.textContent = e.message; msg.hidden = false; }
          } },
            h("div", { class: "field" }, h("label", { for: "off-pw", text: "Password" }), pw),
            h("div", { class: "field" }, h("label", { for: "off-code", text: "Code from your app, or a recovery code" }), code),
            msg, h("div", { class: "row" }, off)));
    }
    const cur = h("input", { type: "password", id: "pw-cur", autocomplete: "current-password" });
    const nw = h("input", { type: "password", id: "pw-new", autocomplete: "new-password", minlength: "12" });
    const again = h("input", { type: "password", id: "pw-again", autocomplete: "new-password" });
    const pmsg = h("p", { class: "notice error", role: "alert", hidden: true });
    const password = h("form", { class: "panel", novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      pmsg.hidden = true;
      if (nw.value !== again.value) { pmsg.textContent = "The new passwords don't match."; pmsg.hidden = false; return; }
      try {
        await api.post("password", { current: cur.value, new: nw.value });
        renderSignIn("Password changed. Sign in with your new password.");
      } catch (e) { pmsg.textContent = e.message; pmsg.hidden = false; }
    } },
      h("h2", { text: "Change password" }),
      h("div", { class: "field" }, h("label", { for: "pw-cur", text: "Current password" }), cur),
      h("div", { class: "field" }, h("label", { for: "pw-new", text: "New password" }), nw,
        h("p", { class: "hint", text: "At least 12 characters. A few unrelated words works well." })),
      h("div", { class: "field" }, h("label", { for: "pw-again", text: "New password again" }), again),
      pmsg, h("div", { class: "row" }, h("button", { type: "submit" }, "Change password")),
      h("p", { class: "small muted", text: "Changing your password signs you out everywhere." }));
    return [h("h1", { text: "Your account" }), h("p", { class: "lede", text: me.email + ", " + me.role + " at " + me.company + "." }),
      twoStep, password];
  }

  // ---------- approvals ----------
  async function renderApprovals() {
    const { tickets } = await api.get("tickets");
    state.waiting = tickets.length;
    const nav = document.querySelector('nav.tabs a[href="#approvals"]');
    if (nav) nav.replaceChildren("Approvals", tickets.length ? h("span", { class: "count", text: " (" + tickets.length + ")" }) : "");
    const canDecide = state.me.role === "admin" || state.me.role === "approver";
    if (!tickets.length) {
      return [h("h1", { text: "Approvals" }), h("div", { class: "empty" },
        h("p", { text: "Nothing is waiting for you." }),
        h("p", { class: "muted", text: "When an agent asks for something that needs a person, it appears here with the reasons. Agents wait until you decide." }))];
    }
    const list = h("ul", { class: "slips", "aria-label": "Waiting for approval" });
    for (const t of tickets) list.append(slip(t, canDecide, list));
    return [
      h("h1", { text: count(tickets.length, "request is", "requests are") + " waiting for you" }),
      h("p", { class: "lede", text: "Highest risk first. Approving lets the agent's action go ahead. Rejecting stops it, and the agent is told not to try again." }),
      canDecide ? null : h("p", { class: "notice", text: "Your role can view these but not decide on them." }),
      list,
    ];
  }

  function slip(t, canDecide, list) {
    const what = {
      pay: "Agent " + t.agent_id + " wants to pay this invoice.",
      change_bank: "Agent " + t.agent_id + " wants to change where this vendor is paid.",
      refund: "Agent " + t.agent_id + " wants to issue this refund.",
      edit_record: "Agent " + t.agent_id + " wants to edit this invoice record.",
    }[t.action];
    const facts = h("dl", { class: "facts" });
    const fact = (label, value, cls) => { if (value) facts.append(h("div", {}, h("dt", { text: label }), h("dd", { class: cls || false, text: value }))); };
    fact("Invoice", t.invoice_number);
    fact("Purchase order", t.po_number || (t.action === "pay" ? "None" : ""));
    fact("Asked by", t.requested_by ? t.requested_by.identity : "Nobody recorded");
    fact("Account on file", t.account_on_file);
    fact("Pays to", t.action === "refund" ? t.pays_to : "");
    fact("Account on the invoice", t.account_on_invoice, t.account_on_invoice && t.account_on_invoice !== t.account_on_file ? "differs" : "");
    fact("New account requested", t.new_account, "differs");
    fact("Evidence", t.evidence.map((e) => e.ref + (e.sender ? " from " + e.sender : "")).join(", "));
    fact("Approvals", t.needed > 1 ? t.approved_by.length + " of " + t.needed + (t.approved_by.length ? " (" + t.approved_by.join(", ") + ")" : "") : "");
    fact("Time left", untilText(t.expires_at));

    const li = h("li", { class: "slip" });
    const status = h("p", { class: "notice error", role: "alert", hidden: true });
    const note = h("textarea", { id: "note-" + t.ticket_id, maxlength: "500", rows: "2" });
    const verb = { pay: "Approve payment", change_bank: "Approve bank change", refund: "Approve refund", edit_record: "Approve edit" }[t.action];
    const approve = h("button", { type: "button" }, verb);
    const reject = h("button", { type: "button", class: "danger" }, "Reject");
    const fraud = h("button", { type: "button", class: "link" }, "Reject and report as fraud");
    let called = null, dialled = null;
    const digits = (s) => (s || "").replace(/\D/g, "");
    const ready = () => !!(called && called.checked && digits(dialled.value) && digits(dialled.value) === digits(t.phone_on_file));
    if (t.action === "change_bank") {
      called = h("input", { type: "checkbox", id: "called-" + t.ticket_id });
      dialled = h("input", { type: "tel", id: "dialled-" + t.ticket_id, autocomplete: "off", inputmode: "tel" });
      approve.disabled = true;
      for (const el of [called, dialled]) el.addEventListener("input", () => { approve.disabled = !ready(); });
      called.addEventListener("change", () => { approve.disabled = !ready(); });
    }

    async function decide(isApprove, isFraud) {
      status.hidden = true;
      for (const b of [approve, reject, fraud]) b.disabled = true;
      try {
        const out = await api.post("tickets/" + t.ticket_id, {
          approve: isApprove, note: note.value, callback_verified: !!(called && called.checked),
          called_number: dialled ? dialled.value : "", fraud: !!isFraud,
        });
        let message;
        if (out.status === "open") message = "Approved. One more person needs to approve.";
        else if (out.status === "approved") message = { pay: "Payment approved", change_bank: "Bank change approved", refund: "Refund approved", edit_record: "Edit approved" }[t.action];
        else if (out.reopened) message = "Not paid yet: something new came up, so it needs approving again. " + (out.reasons || []).join(" ");
        else if (out.status === "blocked_on_recheck") message = "Not approved: something changed since it was paused. " + (out.reasons || []).join(" ");
        else message = isFraud ? "Rejected and reported as fraud" : "Rejected";
        toast(message);
        if (out.status === "open" || out.reopened) return render();
        li.classList.add("leaving");
        setTimeout(() => {
          li.remove();
          state.waiting = Math.max(0, state.waiting - 1);
          if (!list.children.length) render();
          else {
            const h1 = document.querySelector("#main h1");
            if (h1) h1.textContent = count(list.children.length, "request is", "requests are") + " waiting for you";
          }
        }, 200);
      } catch (e) {
        status.textContent = e.message;
        status.hidden = false;
        for (const b of [approve, reject, fraud]) b.disabled = false;
        if (called) approve.disabled = !ready();
      }
    }
    approve.addEventListener("click", () => decide(true, false));
    reject.addEventListener("click", () => decide(false, false));
    fraud.addEventListener("click", () => decide(false, true));

    li.append(
      h("div", { class: "slip-body" },
        h("div", { class: "slip-head" },
          h("div", {}, h("h2", { class: "slip-vendor", text: t.vendor_name }), h("p", { class: "slip-what", text: what })),
          t.amount_cents ? h("p", { class: "slip-amount", text: money(t.amount_cents, t.currency) }) : h("p", { class: "slip-amount", text: ACTION[t.action] })),
        h("div", {}, h("h3", { text: "Why it was paused" }), h("ul", { class: "reasons" }, t.reasons.map((r) => h("li", { text: r })))),
        facts),
      h("div", { class: "stub" },
        canDecide ? [
          called ? h("label", { class: "check", for: called.id }, called,
            h("span", { text: "I called the vendor on " + (t.phone_on_file || "the number on file") + " and they confirmed the new account." })) : null,
          dialled ? h("div", {}, h("label", { for: dialled.id, text: "Number you called (must match the number on file, not one from the request)" }), dialled) : null,
          h("div", {}, h("label", { for: note.id, text: "Note (optional, saved in the audit log)" }), note),
          h("div", { class: "stub-actions" }, approve, reject, h("span", { class: "spacer" }), fraud),
          status,
        ] : h("p", { class: "muted", text: "Waiting for an approver." })));
    return li;
  }

  // ---------- overview ----------
  async function renderOverview() {
    const o = await api.get("overview");
    const stopped = h("ul", { class: "reasons" }, o.stopped.map((s) => h("li", {},
      h("strong", { text: s.vendor_name }), " ", s.amount_cents ? money(s.amount_cents) + " " : "",
      h("span", { class: "muted", text: "(" + dateText(s.on) + ", agent " + s.agent_id + "). " }),
      s.reasons[0] || "")));
    return [
      h("h1", { text: "Overview" }),
      h("div", { class: "panel" },
        h("p", { class: "big-sentence", text: "In the last " + o.days + " days the checkpoint checked " +
          count(o.checked, "action", "actions") + " from " + count(o.agents.length, "agent", "agents") + "." }),
        h("table", { class: "statement" }, h("tbody", {},
          h("tr", {}, h("td", {}, verdictTag("go"), " went straight through"), h("td", { class: "num", text: String(o.allowed) }), h("td", { class: "num", text: money(o.allowed_cents) })),
          h("tr", {}, h("td", {}, verdictTag("pause"), " were sent to a person"), h("td", { class: "num", text: String(o.paused) }), h("td", { class: "num", text: money(o.paused_cents) })),
          h("tr", {}, h("td", {}, verdictTag("block"), o.mode === "enforce" ? " were stopped" : " would have been stopped"), h("td", { class: "num", text: String(o.blocked) }), h("td", { class: "num", text: money(o.blocked_cents) })))),
        h("p", { class: "small muted", text: "Amounts are payments and refunds only. " +
          (o.ledger_ok ? "The audit log is intact." : "The audit log failed its integrity check. Open the Audit log page.") })),
      o.stopped.length ? h("section", { class: "panel" }, h("h2", { text: "Recently stopped" }), stopped) : null,
      h("section", { class: "panel" }, h("h2", { text: "Agents" }),
        h("table", { class: "statement" }, h("tbody", {}, o.agents.map((a) =>
          h("tr", {}, h("td", {}, h("strong", { text: a.agent_id }), a.made_by ? h("span", { class: "muted", text: " (" + a.made_by + ")" }) : null),
            h("td", { class: "num", text: count(a.actions, "action", "actions") })))))),
    ];
  }

  // ---------- activity ----------
  async function renderActivity() {
    const params = new URLSearchParams((location.hash.split("?")[1]) || "");
    const verdict = h("select", { id: "f-verdict" },
      [["", "All decisions"], ["block", "Blocked"], ["pause", "Needs approval"], ["go", "Allowed"]].map(([v, l]) =>
        h("option", { value: v, selected: params.get("verdict") === v }, l)));
    const search = h("input", { type: "search", id: "f-q", value: params.get("q") || "", placeholder: "Vendor or invoice" });
    const tableBox = h("div", {});
    async function load() {
      const qs = new URLSearchParams();
      if (verdict.value) qs.set("verdict", verdict.value);
      if (search.value.trim()) qs.set("q", search.value.trim());
      tableBox.replaceChildren(h("p", { class: "muted", text: "Loading" }));
      try {
        const { rows } = await api.get("activity" + (qs.toString() ? "?" + qs : ""));
        tableBox.replaceChildren(activityTable(rows));
      } catch (e) { tableBox.replaceChildren(errorBox(e)); }
    }
    verdict.addEventListener("change", load);
    let timer;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 250); });
    const exportBtn = h("button", { type: "button", class: "secondary", onclick: async () => {
      try {
        const blob = await api.get("export/activity.csv");
        const url = URL.createObjectURL(blob);
        const a = h("a", { href: url, download: "checkpoint-activity.csv" });
        document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (e) { toast(e.message); }
    } }, "Download CSV");
    load();
    return [
      h("div", { class: "row" }, h("h1", { text: "Activity" }), h("span", { class: "push" }), exportBtn),
      h("div", { class: "filters" },
        h("div", {}, h("label", { for: "f-verdict", text: "Decision" }), verdict),
        h("div", {}, h("label", { for: "f-q", text: "Search" }), search)),
      tableBox,
    ];
  }

  function activityTable(rows) {
    if (!rows.length) return h("div", { class: "empty" }, h("p", { text: "No actions match these filters." }));
    const body = h("tbody", {});
    for (const r of rows) {
      const why = h("tr", { class: "why", hidden: true }, h("td", { colspan: "7" },
        r.reasons.length ? h("ul", { class: "reasons" }, r.reasons.map((x) => h("li", { text: x }))) : "No checks raised anything.",
        h("p", { class: "small muted" }, "Request ", h("span", { class: "code", text: r.request_id }))));
      const toggle = h("button", { type: "button", class: "plain", "aria-expanded": "false" }, "Why");
      toggle.addEventListener("click", () => {
        why.hidden = !why.hidden;
        toggle.setAttribute("aria-expanded", String(!why.hidden));
      });
      body.append(h("tr", {},
        h("td", { text: dateText(r.on) }), h("td", { text: r.agent_id }), h("td", { text: ACTION[r.action] || r.action }),
        h("td", {}, r.vendor_name, r.invoice_number ? h("div", { class: "muted", text: r.invoice_number }) : null),
        h("td", { class: "num", text: r.amount_cents ? money(r.amount_cents) : "" }),
        h("td", {}, verdictTag(r.verdict), h("div", { class: "muted", text: STATUS[r.status] || r.status })),
        h("td", {}, toggle)), why);
    }
    return h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, ["Date", "Agent", "Action", "Vendor", "Amount", "Decision", ""].map((x, i) =>
        h("th", { class: i === 4 ? "num" : false, scope: "col", text: x })))), body));
  }

  // ---------- audit ----------
  function saveFile(text, type, file) {
    if (window.CHECKPOINT_DEMO_NO_DOWNLOADS) return toast("Downloads are turned off in this shared demo.");
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: file });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function evidencePanel(ev) {
    const pct = (v) => v === null || v === undefined ? "not enough data yet" : v + "%";
    const rows = [
      ["Payment files checked", ev.payment_files + " (" + count(ev.lines_checked, "line", "lines") + ")"],
      ["Held for review", ev.lines_held + " (" + ev.held_pct + "%)"],
      ["Held lines that were real problems", ev.held_and_real + " of " + ev.held_lines_reviewed + " with an outcome (" + pct(ev.precision_pct) + ")"],
      ["Fraud that got through", ev.misses_recorded + " recorded (" + money(ev.missed_cents) + "), miss rate " + pct(ev.fraud_miss_rate_pct)],
      ["Releases signed", ev.usage.releases_issued + " (" + money(ev.usage.released_cents) + " released)"],
    ];
    const list = h("button", { type: "button", class: "secondary" }, "Download allowed-accounts list (signed)");
    list.addEventListener("click", async () => {
      try {
        const doc = await api.post("allowed-accounts", {});
        saveFile(JSON.stringify(doc, null, 2) + "\n", "application/json", doc.body.list_id + ".json");
        toast("Allowed-accounts list version " + doc.body.version + " signed");
      } catch (e) { toast(e.message); }
    });
    const key = h("button", { type: "button", class: "secondary" }, "Download public key");
    key.addEventListener("click", () => saveFile(ev.public_key, "application/x-pem-file", "checkpoint-public-key.pem"));
    return h("div", { class: "panel" },
      h("h2", { text: "For your bank and insurer" }),
      h("p", { class: "small muted", text: "A bank or payment system can check a signed release or the allowed-accounts list with the public key alone. It is a control only once their system is set to refuse payments without it." }),
      h("table", { class: "statement facts-long" }, h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("td", { text: k }), h("td", { class: "num", text: v }))))),
      ev.caveats.length ? h("ul", { class: "small muted" }, ev.caveats.map((c) => h("li", { text: c }))) : null,
      h("div", { class: "row" }, state.me.role !== "auditor" ? list : null, key));
  }

  async function renderAudit() {
    const [a, ev] = await Promise.all([api.get("audit"), api.get("evidence")]);
    return [
      h("h1", { text: "Audit log" }),
      h("p", { class: "lede", text: "Every request, decision, approval and payment is written here in order. Each entry is chained to the one before it and signed, so any later change is detected." }),
      h("p", { class: "notice " + (a.ok ? "ok" : "error"), role: "status",
        text: a.ok ? "Intact. " + a.detail.replace("chain intact", "every entry checked") + "." : "Integrity check failed: " + a.detail + "." }),
      h("div", { class: "panel" },
        h("h2", { text: "Latest entry fingerprint" }),
        h("p", { class: "small muted", text: "Send this to your auditor or keep it somewhere outside this system. If entries are ever removed, comparing with it shows it." }),
        h("p", { class: "code", text: "Entry " + a.head.seq + ": " + a.head.hash })),
      evidencePanel(ev),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["#", "Time", "What happened", "Request"].map((x) => h("th", { scope: "col", text: x })))),
        h("tbody", {}, a.recent.map((e) => h("tr", {},
          h("td", { text: String(e.seq) }), h("td", { text: new Date(e.at).toLocaleString("en-US") }),
          h("td", { text: e.summary }), h("td", {}, h("span", { class: "code", text: e.request_id }))))))),
    ];
  }

  // ---------- vendors ----------
  async function renderVendors() {
    const { vendors } = await api.get("vendors");
    const isAdmin = state.me.role === "admin";
    const canRequest = isAdmin || state.me.role === "approver";
    const body = h("tbody", {});
    for (const v of vendors) {
      const panel = h("tr", { class: "why", hidden: true }, h("td", { colspan: "7" }));
      const openPanel = (content) => { panel.firstChild.replaceChildren(content); panel.hidden = false; };
      const actions = h("div", { class: "row" });
      if (isAdmin) {
        const edit = h("button", { type: "button", class: "plain" }, "Edit");
        edit.addEventListener("click", () => openPanel(vendorEditForm(v)));
        actions.append(edit);
      }
      if (canRequest) {
        const bank = h("button", { type: "button", class: "plain" }, "Change bank account");
        bank.addEventListener("click", () => openPanel(bankChangeForm(v)));
        actions.append(bank);
      }
      const cc = v.pending_contact_change;
      let waiting = null;
      if (cc) {
        const what = [];
        if (cc.phone !== v.phone) what.push("phone to " + (cc.phone || "none"));
        if (cc.email_domains.join(",") !== v.email_domains.join(",")) what.push("email domains to " + (cc.email_domains.join(", ") || "none"));
        waiting = h("div", { class: "notice" }, h("span", { text: cc.requested_by + " asked to change " + what.join(" and ") + ". " }));
        if (canRequest && cc.requested_by.toLowerCase() !== state.me.email.toLowerCase()) {
          for (const [label, ok] of [["Approve change", true], ["Reject", false]]) {
            const btn = h("button", { type: "button", class: ok ? "" : "secondary" }, label);
            btn.addEventListener("click", async () => {
              btn.disabled = true;
              try { await api.post("contact-changes/" + cc.change_id, { approve: ok }); toast(ok ? "Change approved" : "Change rejected"); render(); }
              catch (e) { toast(e.message); btn.disabled = false; }
            });
            waiting.append(btn);
          }
          waiting.append(h("p", { class: "small muted", text: "Check it with the vendor using the details on file now, not the new ones. After a change, bank changes for this vendor wait " + (state.me.contact_cooldown_days || 14) + " days." }));
        } else {
          waiting.append(h("span", { class: "muted", text: "Someone else needs to approve it." }));
        }
      }
      body.append(h("tr", {},
        h("td", {}, h("strong", { text: v.name }), h("div", { class: "muted", text: v.vendor_id }), waiting),
        h("td", { text: v.account_on_file }), h("td", { text: v.email_domains.join(", ") || "None" }),
        h("td", { text: v.bank_changed_on ? dateText(v.bank_changed_on) : "Never" }),
        h("td", { class: "num", text: String(v.payments) }), h("td", { class: "num", text: money(v.paid_cents) }),
        h("td", {}, actions)), panel);
    }
    return [
      h("div", { class: "row" }, h("h1", { text: "Vendors" })),
      h("p", { class: "lede", text: "Payments always go to the account on file here. A bank account only changes through a request that a different person approves after phoning the vendor." }),
      vendors.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["Vendor", "Account on file", "Email domains", "Bank changed", "Payments", "Paid", ""].map((x, i) =>
          h("th", { scope: "col", class: i === 4 || i === 5 ? "num" : false, text: x })))), body))
        : h("div", { class: "empty" }, h("p", { text: "No vendors yet. Import your vendor list on the Setup page, or add one below." })),
      isAdmin ? addVendorForm() : null,
    ];
  }

  function vendorEditForm(v) {
    const msg = formMessage();
    const name = h("input", { type: "text", id: "ve-name-" + v.vendor_id, value: v.name, maxlength: "200" });
    const domains = h("input", { type: "text", id: "ve-dom-" + v.vendor_id, value: v.email_domains.join(", ") });
    const phone = h("input", { type: "text", id: "ve-ph-" + v.vendor_id, value: v.phone || "", maxlength: "40" });
    return h("form", { novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      try {
        const out = await api.post("vendors/" + encodeURIComponent(v.vendor_id), { name: name.value, email_domains: domains.value, phone: phone.value });
        toast(out.contact_change ? "Saved. The phone or email change needs another person to approve it." : "Vendor saved"); render();
      } catch (e) { showMessage(msg, false, e.message); }
    } }, field(name.id, "Name", name), field(domains.id, "Email domains", domains, "Separate with commas, e.g. northwind.com, northwind-billing.com"),
      field(phone.id, "Phone number for confirming bank changes", phone, "Changes to the phone or email domains take effect when someone else approves them."),
      h("p", { class: "small muted", text: "The bank account can't be edited here. Use Change bank account." }),
      h("div", { class: "row" }, h("button", { type: "submit" }, "Save vendor")), msg);
  }

  function bankChangeForm(v) {
    const msg = formMessage();
    const acct = h("input", { type: "text", id: "bc-" + v.vendor_id, maxlength: "64", autocomplete: "off" });
    const note = h("input", { type: "text", id: "bcn-" + v.vendor_id, maxlength: "300", placeholder: "e.g. Letter from vendor dated Nov 10" });
    return h("form", { novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      try {
        const d = await api.post("vendors/" + encodeURIComponent(v.vendor_id) + "/bank-change", { new_account: acct.value.trim(), note: note.value.trim() });
        showMessage(msg, d.verdict !== "block", d.verdict === "block" ? "Blocked: " + d.findings.map((f) => f.message).join(" ")
          : "Request sent for approval. Another approver must phone the vendor on the number on file before approving it.");
      } catch (e) { showMessage(msg, false, e.message); }
    } }, h("p", { text: "Account on file now: " + v.account_on_file + ". The change needs a different approver, who must call the vendor on the number on file." }),
      field(acct.id, "New bank account", acct), field(note.id, "Where the new details came from", note),
      h("div", { class: "row" }, h("button", { type: "submit" }, "Request bank change")), msg);
  }

  function addVendorForm() {
    const msg = formMessage();
    const inputs = {
      vendor_id: h("input", { type: "text", id: "nv-id", maxlength: "64" }), name: h("input", { type: "text", id: "nv-name", maxlength: "200" }),
      bank_account: h("input", { type: "text", id: "nv-bank", maxlength: "64", autocomplete: "off" }),
      email_domains: h("input", { type: "text", id: "nv-dom" }), phone: h("input", { type: "text", id: "nv-phone", maxlength: "40" }),
    };
    return h("details", { class: "more panel" }, h("summary", { text: "Add a vendor" }),
      h("form", { novalidate: true, onsubmit: async (ev) => {
        ev.preventDefault();
        try {
          await api.post("vendors", Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, el.value.trim()])));
          toast("Vendor added"); render();
        } catch (e) { showMessage(msg, false, e.message); }
      } }, field("nv-id", "Vendor ID (as in your accounting system)", inputs.vendor_id), field("nv-name", "Name", inputs.name),
        field("nv-bank", "Bank account", inputs.bank_account), field("nv-dom", "Email domains", inputs.email_domains, "So emails claiming to be from this vendor can be checked."),
        field("nv-phone", "Phone number", inputs.phone, "Used to confirm any future bank change."),
        h("div", { class: "row" }, h("button", { type: "submit" }, "Add vendor")), msg));
  }

  // ---------- shared bits for forms ----------
  function field(id, label, input, hint) {
    input.id = input.id || id;
    return h("div", { class: "field" }, h("label", { for: input.id, text: label }), input,
      hint ? h("p", { class: "hint", text: hint }) : null);
  }
  function formMessage() { return h("p", { role: "status", hidden: true }); }
  function showMessage(el, ok, text) { el.className = ok ? "notice ok" : "notice error"; el.textContent = text; el.hidden = false; }
  function once(title, secret, note, extra) {
    const copy = h("button", { type: "button", class: "secondary" }, "Copy");
    copy.addEventListener("click", () => copyText(secret, "Copied"));
    return h("div", { class: "notice ok" }, h("p", {}, h("strong", { text: title })),
      h("p", { class: "key", text: secret }), h("div", { class: "row" }, copy),
      h("p", { class: "small", text: note }), extra || null);
  }

  // ---------- setup ----------
  async function renderSettings() {
    const [s, setup] = await Promise.all([api.get("settings"), api.get("setup")]);
    const isAdmin = state.me.role === "admin";
    const parts = [h("h1", { text: "Setup" }), checklist(setup), rulesForm(s, isAdmin), recordsPanel(isAdmin),
      agentsPanel(s, isAdmin), peoplePanel(s.users, isAdmin)];
    return parts;
  }

  function checklist(setup) {
    return h("section", { class: "panel" },
      h("h2", { text: "Getting started (" + setup.done + " of " + setup.steps.length + " done)" }),
      h("ol", { class: "checklist" }, setup.steps.map((st) => h("li", { class: st.done ? "done" : "" },
        h("span", { class: "verdict " + (st.done ? "go" : "pause"), text: st.done ? "Done" : "To do" }), " ",
        h("strong", { text: st.title }), h("div", { class: "muted small", text: st.detail })))),
      setup.health.map((x) => h("p", { class: x.level === "warn" ? "notice" : "small muted", text: x.text })));
  }

  function rulesForm(s, isAdmin) {
    const msg = formMessage();
    const dollars = (c) => (c / 100).toFixed(2);
    const modeShadow = h("input", { type: "radio", name: "mode", id: "mode-shadow", value: "shadow", checked: s.mode === "shadow", disabled: !isAdmin });
    const modeEnforce = h("input", { type: "radio", name: "mode", id: "mode-enforce", value: "enforce", checked: s.mode === "enforce", disabled: !isAdmin });
    const limit = h("input", { type: "text", inputmode: "decimal", value: dollars(s.approval_limit_cents), disabled: !isAdmin });
    const dual = h("input", { type: "text", inputmode: "decimal", value: dollars(s.dual_approval_cents), disabled: !isAdmin });
    const days = h("input", { type: "number", min: "1", max: "365", value: s.recent_bank_change_days, disabled: !isAdmin });
    const hours = h("input", { type: "number", min: "1", max: "720", value: s.ticket_hours, disabled: !isAdmin });
    const require2 = h("input", { type: "checkbox", id: "s-2step", checked: s.require_two_step, disabled: !isAdmin });
    const save = h("button", { type: "submit" }, "Save rules");
    return h("form", { class: "panel", novalidate: true, onsubmit: async (ev) => {
      ev.preventDefault();
      msg.hidden = true;
      save.disabled = true;
      try {
        await api.post("settings", {
          mode: modeEnforce.checked ? "enforce" : "shadow", approval_limit: limit.value.trim(),
          dual_approval_limit: dual.value.trim(), recent_bank_change_days: Number(days.value), ticket_hours: Number(hours.value),
          require_two_step: require2.checked,
        });
        state.me = await api.get("me");
        toast("Rules saved");
        render();
      } catch (e) { showMessage(msg, false, e.message); save.disabled = false; }
    } },
      h("h2", { text: "Rules" }),
      h("fieldset", { class: "field" }, h("legend", { text: "Mode" }),
        h("label", { class: "check", for: "mode-shadow" }, modeShadow, h("span", { text: "Watch only: record what would be stopped, block nothing" })),
        h("label", { class: "check", for: "mode-enforce" }, modeEnforce, h("span", { text: "Enforce: agents wait for checks and approvals" }))),
      field("s-limit", "Payments at or above this amount need a person (USD)", limit),
      field("s-dual", "At or above this amount, two different people must approve (USD)", dual),
      field("s-days", "Hold payments to a newly changed bank account for this many days", days),
      field("s-hours", "Reject requests nobody answers within this many hours", hours),
      h("div", { class: "field" }, h("label", { class: "check", for: "s-2step" }, require2,
        h("span", { text: "Require two-step sign-in for everyone who signs in with a password" })),
        h("p", { class: "hint", text: "People without it are asked to set it up at their next sign-in. Company single sign-on counts as two-step." })),
      isAdmin ? h("div", { class: "row" }, save) : h("p", { class: "muted", text: "Only admins can change these." }), msg);
  }

  function recordsPanel(isAdmin) {
    if (!isAdmin) return null;
    const order = h("select", { id: "hist-order" }, h("option", { value: "mdy" }, "Month first (03/14/2026)"),
      h("option", { value: "dmy" }, "Day first (14/03/2026)"));
    return h("section", { class: "panel" },
      h("h2", { text: "Your records" }),
      h("p", { class: "small muted", text: "Export from your accounting system or Excel and save as CSV UTF-8 (in Excel: File, Save As). Column names are matched by meaning, so \"Supplier\", \"Vendor name\" and \"Payee\" all work. Files up to 1 MB. Importing never changes an existing vendor's bank account." }),
      uploadField("import/vendors", "Vendor list", "Needs: name and bank account. Also useful: vendor ID, email domain, phone number."),
      uploadField("import/pos", "Open purchase orders", "Needs: PO number, vendor, amount."),
      h("div", { class: "field" }, h("label", { for: "hist-order", text: "Dates in your payment history file are" }), order),
      uploadField("import/history", "Past payments (6 to 12 months)", "Needs: vendor, invoice number, amount, payment date. Importing the same file twice adds nothing twice.", () => "?date_order=" + order.value),
      addPoForm());
  }

  function addPoForm() {
    const msg = formMessage();
    const vendor = h("select", { id: "po-vendor" }, h("option", { value: "" }, "Loading vendors"));
    api.get("vendors").then((r) => vendor.replaceChildren(h("option", { value: "" }, "Choose a vendor"),
      ...r.vendors.map((v) => h("option", { value: v.vendor_id }, v.name)))).catch(() => {});
    const number = h("input", { type: "text", id: "po-number", maxlength: "64" });
    const amount = h("input", { type: "text", id: "po-amount", inputmode: "decimal" });
    return h("details", { class: "more" }, h("summary", { text: "Add one purchase order" }),
      h("form", { novalidate: true, onsubmit: async (ev) => {
        ev.preventDefault();
        try {
          await api.post("pos", { number: number.value.trim(), vendor_id: vendor.value, amount: amount.value.trim() });
          showMessage(msg, true, "Purchase order " + number.value.trim() + " added.");
          number.value = ""; amount.value = "";
        } catch (e) { showMessage(msg, false, e.message); }
      } }, field("po-vendor", "Vendor", vendor), field("po-number", "PO number", number), field("po-amount", "Amount (USD)", amount),
        h("div", { class: "row" }, h("button", { type: "submit" }, "Add purchase order")), msg));
  }

  function agentsPanel(s, isAdmin) {
    const actionsLabel = (xs) => xs.map((x) => ACTION[x] || x).join(", ");
    const rows = s.agents.map((a) => {
      const remove = h("button", { type: "button", class: "plain" }, "Remove");
      remove.addEventListener("click", async () => {
        if (remove.dataset.armed !== "1") { remove.dataset.armed = "1"; remove.textContent = "Click again to remove"; return; }
        try { await api.post("agents/" + encodeURIComponent(a.agent_id) + "/remove", {}); toast("Agent removed; its keys no longer work"); render(); }
        catch (e) { toast(e.message); }
      });
      return h("tr", {}, h("td", {}, h("strong", { text: a.agent_id }), h("div", { class: "muted", text: a.made_by || "" })),
        h("td", { text: actionsLabel(a.allowed_actions) }), h("td", { class: "num", text: money(a.max_amount_cents) }),
        h("td", { class: "num", text: money(a.daily_cap_cents) }), h("td", {}, isAdmin ? remove : ""));
    });
    return h("section", { class: "panel" }, h("h2", { text: "Agents" }),
      h("p", { class: "small muted", text: "Each agent gets its own key and limits. Give agents these tools instead of direct access to your bank or accounting system; otherwise they can go around the checkpoint." }),
      s.agents.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["Agent", "Allowed to", "Limit per action", "Daily limit", ""].map((x, i) =>
          h("th", { scope: "col", class: i === 2 || i === 3 ? "num" : false, text: x })))), h("tbody", {}, rows)))
        : h("p", { class: "muted", text: "No agents yet." }),
      isAdmin ? addAgentForm() : null);
  }

  function addAgentForm() {
    const msg = formMessage();
    const out = h("div", {});
    const name = h("input", { type: "text", id: "ag-name", maxlength: "41", placeholder: "ap-agent" });
    const madeBy = h("input", { type: "text", id: "ag-by", maxlength: "80", placeholder: "Claude, Salesforce, in-house" });
    const boxes = Object.keys(ACTION).map((k) => h("input", { type: "checkbox", id: "ag-" + k, value: k, checked: k === "pay" }));
    const max = h("input", { type: "text", id: "ag-max", inputmode: "decimal", value: "25000" });
    const day = h("input", { type: "text", id: "ag-day", inputmode: "decimal", value: "100000" });
    return h("details", { class: "more" }, h("summary", { text: "Connect a new agent" }),
      h("form", { novalidate: true, onsubmit: async (ev) => {
        ev.preventDefault();
        msg.hidden = true;
        try {
          const r = await api.post("agents", { agent_id: name.value.trim().toLowerCase(), made_by: madeBy.value.trim(),
            allowed_actions: boxes.filter((b) => b.checked).map((b) => b.value), max_amount: max.value.trim(), daily_cap: day.value.trim() });
          const config = JSON.stringify({ mcpServers: { "agent-checkpoint": { command: "agent-checkpoint",
            args: ["mcp", "--url", location.origin], env: { CHECKPOINT_AGENT_KEY: r.key } } } }, null, 2);
          const copyConfig = h("button", { type: "button", class: "secondary" }, "Copy MCP config");
          copyConfig.addEventListener("click", () => copyText(config, "MCP config copied"));
          out.replaceChildren(once("Key for " + r.agent_id + " (shown once)", r.key,
            "Store it like a password. If it's lost, remove the agent and connect it again.",
            h("div", {}, h("p", { class: "small", text: "For Claude or any MCP client, add this to its MCP settings:" }),
              h("pre", { class: "config", text: config }), copyConfig,
              h("p", { class: "small", text: "Other agents call the HTTP API at " + location.origin + "/v1/actions with the header Authorization: Bearer <key>." }))));
          name.value = "";
        } catch (e) { showMessage(msg, false, e.message); }
      } },
        field("ag-name", "Agent name", name, "Lowercase letters, digits and dashes."),
        field("ag-by", "Made by (optional)", madeBy),
        h("fieldset", { class: "field" }, h("legend", { text: "Allowed to" }),
          boxes.map((b) => h("label", { class: "check", for: b.id }, b, h("span", { text: ACTION[b.value] })))),
        field("ag-max", "Limit per action (USD)", max), field("ag-day", "Daily limit (USD)", day),
        h("div", { class: "row" }, h("button", { type: "submit" }, "Create agent and key")), msg), out);
  }

  function peoplePanel(users, isAdmin) {
    const rows = users.map((u) => {
      const actions = h("div", { class: "row" });
      if (isAdmin && u.email !== state.me.email) {
        const toggle = h("button", { type: "button", class: "plain" }, u.disabled ? "Enable" : "Disable");
        toggle.addEventListener("click", () => personAction(u.email, u.disabled ? "enable" : "disable"));
        actions.append(toggle);
      }
      if (isAdmin && u.two_step) {
        const reset = h("button", { type: "button", class: "plain" }, "Reset two-step");
        reset.addEventListener("click", () => personAction(u.email, "reset-two-step"));
        actions.append(reset);
      }
      return h("tr", {}, h("td", { text: u.email }), h("td", { text: u.role }),
        h("td", { class: "muted", text: (u.two_step ? "Two-step on" : "Two-step off") + (u.disabled ? ", disabled" : "") }),
        h("td", {}, actions));
    });
    return h("section", { class: "panel" }, h("h2", { text: "People" }),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["Email", "Role", "Status", ""].map((x) => h("th", { scope: "col", text: x })))),
        h("tbody", {}, rows))),
      h("p", { class: "small muted", text: "Admins change settings and records and can approve. Approvers approve. Auditors can see everything and change nothing." }),
      isAdmin ? addPersonForm() : null);
  }

  async function personAction(email, what) {
    try {
      await api.post("people/" + encodeURIComponent(email) + "/" + what, {});
      toast({ disable: "Disabled; their sessions ended", enable: "Enabled", "reset-two-step": "Two-step reset; they set it up again at sign-in" }[what]);
      render();
    } catch (e) { toast(e.message); }
  }

  function addPersonForm() {
    const msg = formMessage();
    const out = h("div", {});
    const email = h("input", { type: "email", id: "pp-email", autocomplete: "off" });
    const role = h("select", { id: "pp-role" }, ["approver", "auditor", "admin"].map((r) => h("option", { value: r }, r)));
    return h("details", { class: "more" }, h("summary", { text: "Add a person" }),
      h("form", { novalidate: true, onsubmit: async (ev) => {
        ev.preventDefault();
        msg.hidden = true;
        try {
          const r = await api.post("people", { email: email.value.trim(), role: role.value });
          out.replaceChildren(once("Temporary password for " + r.email + " (shown once)", r.temporary_password,
            "Send it to them privately. They should change it under Your account after signing in."));
          email.value = "";
        } catch (e) { showMessage(msg, false, e.message); }
      } }, field("pp-email", "Email", email), field("pp-role", "Role", role),
        h("div", { class: "row" }, h("button", { type: "submit" }, "Add person")), msg), out);
  }

  function uploadField(path, label, hint, extra) {
    const input = h("input", { type: "file", id: "up-" + path.replace(/\W/g, "-"), accept: ".csv,text/csv" });
    const out = h("p", { class: "small", role: "status" });
    input.addEventListener("change", async () => {
      const file = input.files && input.files[0];
      out.className = "small";
      if (!file) return;
      if (file.size > 1024 * 1024) { out.className = "notice error"; out.textContent = "That file is over 1 MB."; return; }
      if (!/\.csv$/i.test(file.name)) { out.className = "notice error"; out.textContent = "Choose a .csv file. In Excel: File, Save As, CSV UTF-8."; return; }
      out.textContent = "Importing";
      try {
        const r = await api.upload(path + (extra ? extra() : ""), await file.text());
        out.className = r.errors.length ? "notice error" : "notice ok";
        out.textContent = "Imported " + r.imported + " rows." + (r.already_there ? " " + r.already_there + " were already there." : "") +
          (r.errors.length ? " Skipped: " + r.errors.join("; ") : "");
      } catch (e) { out.className = "notice error"; out.textContent = e.message; }
      input.value = "";
    });
    return h("div", { class: "field" }, h("label", { for: input.id, text: label }), input,
      hint ? h("p", { class: "hint", text: hint }) : null, out);
  }

  // ---------- payment run ----------
  const RUN = { go: "Ready to pay", pause: "Review first", block: "Don't pay" };
  const runTag = (v) => h("span", { class: "verdict " + v, text: RUN[v] });

  async function renderPaymentRun() {
    const canRun = state.me.role === "admin" || state.me.role === "approver";
    const results = h("div", {});
    const input = h("input", { type: "file", id: "run-file", accept: ".csv,text/csv", disabled: !canRun });
    const go = h("button", { type: "button", disabled: !canRun }, "Check this payment run");
    async function run(text, name) {
      results.replaceChildren(h("p", { class: "muted", text: "Checking " + name }));
      try {
        const r = await api.upload("payment-run", text);
        results.replaceChildren(...runResults(r, name));
      } catch (e) { results.replaceChildren(errorBox(e)); }
    }
    go.addEventListener("click", async () => {
      const file = input.files && input.files[0];
      if (!file) return toast("Choose a CSV file first.");
      if (file.size > 1024 * 1024) return toast("That file is over 1 MB.");
      run(await file.text(), file.name);
    });
    const sample = window.CHECKPOINT_DEMO && window.CHECKPOINT_DEMO.payment_run_sample;
    const sampleBtn = sample ? h("button", { type: "button", class: "secondary" }, "Use the sample payment run") : null;
    if (sampleBtn) sampleBtn.addEventListener("click", () => results.replaceChildren(...runResults(sample, "the sample payment run")));
    return [
      h("h1", { text: "Check a payment run" }),
      h("p", { class: "lede", text: "Upload the bills you're about to pay, before you release them. Each line is checked against the account on file, duplicates in this file and in past payments, purchase orders, splits and unusual amounts. A line is not held only because it is over the approval limit: you are already releasing this file. Nothing is paid or changed; the check is recorded in the audit log." }),
      h("div", { class: "panel" },
        field("run-file", "Payment run (CSV)", input, "Needs: vendor and amount. Also useful: invoice number, bank account the payment goes to, PO number. Up to 1 MB."),
        h("div", { class: "row" }, go, sampleBtn),
        canRun ? null : h("p", { class: "muted", text: "Admins and approvers can check payment runs." })),
      results,
    ];
  }

  function runResults(r, name) {
    const sum = r.summary;
    const csv = () => {
      const cell = (v) => { let s = String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const lines = [["Line", "Vendor", "Invoice", "Amount", "Decision", "Reasons"]].concat(r.rows.map((x) =>
        [x.line, x.vendor_name, x.invoice_number, (x.amount_cents / 100).toFixed(2), RUN[x.verdict], x.reasons.join("; ")]));
      return lines.map((l) => l.map(cell).join(",")).join("\n");
    };
    const save = (text, type, file) => {
      if (window.CHECKPOINT_DEMO_NO_DOWNLOADS) return toast("Downloads are turned off in this shared demo.");
      const url = URL.createObjectURL(new Blob([text], { type }));
      const a = h("a", { href: url, download: file });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    const dl = h("button", { type: "button", class: "secondary" }, "Download results (CSV)");
    dl.addEventListener("click", () => save(csv(), "text/csv", "payment-run-checked.csv"));
    const ready = sum.go.count;
    const canRelease = r.run_id && ready > 0 && state.me && state.me.role !== "auditor";
    const rel = canRelease ? h("button", { type: "button" }, "Sign release for " + count(ready, "ready line", "ready lines")) : null;
    const relNote = h("p", { class: "muted", hidden: true });
    if (rel) rel.addEventListener("click", async () => {
      rel.disabled = true;
      try {
        const doc = await api.post("payment-run/" + r.run_id + "/release", {});
        save(JSON.stringify(doc, null, 2) + "\n", "application/json", r.run_id + "-release.json");
        relNote.textContent = "Signed. Send the release with the file to whoever releases payments. If their system checks it, "
          + "only the ready lines go, and only to the accounts on file. Held lines stay held.";
        relNote.hidden = false;
        rel.textContent = "Release signed";
      } catch (e) { toast(e.message); rel.disabled = false; }
    });
    const p = r.pilot;
    const fit = p ? h("p", { class: p.over_limit ? "notice error" : "muted",
      text: p.not_ready + " of " + p.lines + " lines are not ready (" + p.not_ready_pct + "%)."
        + (p.over_limit ? " That's over " + p.limit_pct + "%: on an ordinary file, the checks don't fit these books yet. "
          + "Look at what's being held before relying on it." : "") }) : null;
    return [
      h("div", { class: "panel" },
        h("p", { class: "big-sentence", text: "Checked " + count(r.rows.length, "payment", "payments") + " in " + name + "." }),
        h("table", { class: "statement" }, h("tbody", {}, ["go", "pause", "block"].map((v) => h("tr", {},
          h("td", {}, runTag(v)), h("td", { class: "num", text: String(sum[v].count) }), h("td", { class: "num", text: money(sum[v].amount_cents) }))))),
        fit,
        r.errors && r.errors.length ? h("p", { class: "notice error", text: "Rows that couldn't be read: " + r.errors.join("; ") }) : null,
        h("div", { class: "row" }, rel, dl), relNote),
      h("div", { class: "table-wrap" }, h("table", { class: "data" },
        h("thead", {}, h("tr", {}, ["Line", "Vendor", "Invoice", "Amount", "Decision", "Why"].map((x, i) =>
          h("th", { scope: "col", class: i === 3 ? "num" : false, text: x })))),
        h("tbody", {}, r.rows.map((x) => h("tr", {},
          h("td", { text: String(x.line) }), h("td", { text: x.vendor_name }), h("td", { text: x.invoice_number }),
          h("td", { class: "num", text: money(x.amount_cents) }), h("td", {}, runTag(x.verdict)),
          h("td", {}, x.reasons.length ? h("ul", { class: "reasons" }, x.reasons.map((m) => h("li", { text: m })))
            : h("span", { class: "muted", text: "No problems found." }))))))),
    ];
  }

  window.addEventListener("hashchange", () => { if (state.me) render(); });
  start();
})();
