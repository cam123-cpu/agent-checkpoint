// In-browser stand-in for the server, used only by the sample-data demo.
// It answers the same calls as /api/web/* from a snapshot made by build_demo.py, and keeps
// approvals in memory, so the demo is fully clickable without any server or real data.
"use strict";

(function () {
  const D = JSON.parse(JSON.stringify(window.CHECKPOINT_DEMO));
  const shift = Date.now() - new Date(D.now).getTime(); // make "expires in" read as if it were then
  for (const t of D.tickets) t.expires_at = new Date(new Date(t.expires_at).getTime() + shift).toISOString();
  let signedIn = true;
  window.CHECKPOINT_DEMO_NO_DOWNLOADS = window.self !== window.top; // shared pages run in a frame that blocks downloads
  let seq = D.audit.head.seq;

  window.CHECKPOINT_DEMO_NOTE =
    "Demo with sample data from a simulated quarter at a made-up company. Approvals and settings change only in this browser tab.";

  function fail(status, message) {
    const E = window.CheckpointApiError || Error;
    throw new E(status, message);
  }

  function logEntry(kind, requestId, summary) {
    seq += 1;
    D.audit.head = { seq, hash: Math.random().toString(16).slice(2, 10) + Math.random().toString(16).slice(2, 10) };
    D.audit.recent.unshift({ seq, at: new Date().toISOString(), kind, request_id: requestId, summary, hash: D.audit.head.hash });
  }

  const csvCell = (v) => {
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };

  window.CHECKPOINT_BACKEND = {
    async call(method, path, body) {
      await new Promise((r) => setTimeout(r, 120));
      const [route, qs] = path.split("?");
      const params = new URLSearchParams(qs || "");
      if (route === "login" && method === "POST") { signedIn = true; return { signed_in: true }; }
      if (route === "sso") return { enabled: false, label: "" };
      if (route.startsWith("two-step/") || route === "password")
        fail(403, "Account changes are turned off in this demo. In the real app this sets up two-step sign-in or changes your password.");
      if (route === "logout" && method === "POST") { signedIn = false; return { signed_out: true }; }
      if (!signedIn) fail(401, "Sign in to continue. In this demo any email and a 12-character password work.");
      if (route === "me") return D.me;
      if (route === "overview") return Object.assign({}, D.overview, { waiting: D.tickets.length, mode: D.me.mode });
      if (route === "tickets" && method === "GET") return { tickets: D.tickets };
      if (route.startsWith("tickets/") && method === "POST") {
        const id = route.split("/")[1];
        const t = D.tickets.find((x) => x.ticket_id === id);
        if (!t) fail(404, "That request was already decided.");
        if (body.approve && t.action === "change_bank" && !body.callback_verified)
          fail(422, "Bank changes need a phone call to the number on file first.");
        const row = D.activity.find((r) => r.request_id === t.request_id);
        if (body.approve) {
          t.approved_by.push(D.me.email);
          if (t.approved_by.length < t.needed) {
            t.approved_by[t.approved_by.length - 1] = D.me.email;
            logEntry("human_decision", t.request_id, D.me.email + ": approved (1 of " + t.needed + ")");
            // In the demo, the second approver is simulated so the flow can be seen end to end.
            t.needed = t.approved_by.length;
            return { status: "open", approvals: 1, needed: 2 };
          }
          if (row) row.status = "approved";
          logEntry("human_decision", t.request_id, D.me.email + ": approved");
          logEntry("executed", t.request_id, t.action + " executed");
        } else {
          if (row) row.status = "rejected";
          logEntry("human_decision", t.request_id, D.me.email + ": rejected" + (body.fraud ? ", reported as fraud" : ""));
        }
        D.tickets = D.tickets.filter((x) => x !== t);
        return { status: body.approve ? "approved" : "rejected" };
      }
      if (route === "activity") {
        const v = params.get("verdict") || "";
        const q = (params.get("q") || "").toLowerCase();
        return { rows: D.activity.filter((r) => (!v || r.verdict === v) &&
          (!q || r.vendor_name.toLowerCase().includes(q) || r.invoice_number.toLowerCase().includes(q))) };
      }
      if (route === "audit") return D.audit;
      if (route === "evidence") return D.evidence;
      if (route === "allowed-accounts" || route.endsWith("/release"))
        fail(403, "Signing is turned off in this demo. In the real app an approver signs it with the company's key, for the bank to check.");
      if (route === "vendors" && method === "GET") return { vendors: D.vendors };
      if (route === "setup") return D.setup;
      if (route === "payment-run") fail(403, "Uploading is turned off in this demo. Use the sample payment run instead.");
      if (method === "POST" && /^(vendors|pos|agents|people)(\/|$)/.test(route))
        fail(403, "Changing records is turned off in this demo. In the real app, admins do this here.");
      if (route === "settings" && method === "GET") return D.settings;
      if (route === "settings" && method === "POST") {
        const toCents = (s) => Math.round(Number(String(s).replace(/,/g, "")) * 100);
        const a = toCents(body.approval_limit), b = toCents(body.dual_approval_limit);
        if (!(a > 0) || !(b > 0)) fail(422, "Amounts must look like 10000 or 10000.00.");
        if (b < a) fail(422, "The two-person amount must be at least the approval amount.");
        Object.assign(D.settings, { mode: body.mode, approval_limit_cents: a, dual_approval_cents: b,
          recent_bank_change_days: body.recent_bank_change_days, ticket_hours: body.ticket_hours });
        D.me.mode = body.mode;
        logEntry("settings_changed", "-", "settings changed by " + D.me.email);
        return D.settings;
      }
      if (route.startsWith("import/")) fail(403, "Imports are turned off in the demo.");
      if (route === "export/activity.csv" && window.CHECKPOINT_DEMO_NO_DOWNLOADS) {
        fail(403, "Downloads are turned off in this shared demo. The real app downloads a CSV file here.");
      }
      if (route === "export/activity.csv") {
        const lines = [["Date", "Agent", "Action", "Vendor", "Invoice", "Amount", "Decision", "Status", "Reasons", "Request id"]];
        for (const r of D.activity) lines.push([r.on, r.agent_id, r.action, r.vendor_name, r.invoice_number,
          r.amount_cents ? (r.amount_cents / 100).toFixed(2) : "", r.verdict, r.status, r.reasons.join("; "), r.request_id]);
        return new Blob([lines.map((l) => l.map(csvCell).join(",")).join("\n")], { type: "text/csv" });
      }
      fail(404, "Not available in the demo.");
    },
  };
})();
