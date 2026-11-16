"""Quality bar on the simulated quarter: a regression test, like the invoice detector's evaluate.py."""

from agent_checkpoint.models import Verdict
from agent_checkpoint.sandbox import make_intel
from agent_checkpoint.simulate import network_demo, run, score


def test_shadow_quarter():
    gw, results = run("shadow")
    s = score(gw, results)
    assert s["incidents_stopped"] == s["incidents"] == 12
    assert s["policy_holds_paused"] == s["policy_holds"]
    assert s["clean_interrupted"] <= 0.1 * s["clean"]
    assert s["max_ms"] < 100 and gw.org.ledger.verify()[0]


def test_enforce_quarter_and_network():
    intel = make_intel()
    gw, results = run("enforce", decide=lambda label, raw: label == "policy_hold", intel=intel)
    s = score(gw, results)
    assert s["incidents_stopped"] == s["incidents"] and s["money_lost_cents"] == 0
    assert s["clean_interrupted"] <= 1
    assert network_demo(intel).verdict is Verdict.BLOCK


def test_across_seeds():
    stopped = total = fa = clean = 0
    for seed in range(5):
        gw, results = run("enforce", seed=seed, decide=lambda label, raw: label == "policy_hold")
        s = score(gw, results)
        stopped, total = stopped + s["incidents_stopped"], total + s["incidents"]
        fa, clean = fa + s["clean_interrupted"], clean + s["clean"]
    assert stopped / total >= 0.9 and fa / clean <= 0.02
