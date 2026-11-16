"""House rules for the web app's code and look, enforced on every change.

Safety: no HTML injection sinks, no eval, nothing third-party.
Design: none of the habits that make an app look machine-made (the "20 reasons your app looks
vibecoded" list): no gradients, glass, emoji, icon kits, em dashes, fade-in on scroll,
opacity-fade hovers, all-caps labels, italic serif accents, trendy default fonts or grain.
Accessibility: every text colour pair passes WCAG AA (4.5:1) in light and dark mode.
"""

import os
import re

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
WEB = os.path.join(ROOT, "src", "agent_checkpoint", "web")
FILES = [os.path.join(WEB, f) for f in ("app.js", "app.css", "index.html")] + [os.path.join(ROOT, "scripts", "demo.js")]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


ALL = {os.path.basename(p): read(p) for p in FILES}
CSS = ALL["app.css"]
JS = ALL["app.js"] + ALL["demo.js"]

BANNED = {
    # safety
    "innerHTML": "inserts HTML; use textContent", "outerHTML": "inserts HTML", "insertAdjacentHTML": "inserts HTML",
    "document.write": "inserts HTML", "eval(": "runs strings as code", "new Function": "runs strings as code",
    "http://": "loads from another site", "https://": "loads from another site", "<script>": "inline script",
    " onclick=": "inline handler", "style=": "inline style (blocked by the CSP)",
    # design: the vibecoded list
    "gradient(": "1, 2, 20: gradients", "background-clip: text": "2: gradient text", "backdrop-filter": "6: glassmorphism",
    "Inter": "4: Inter everywhere", "Space Grotesk": "19", "Instrument Serif": "19", "lucide": "10: icon kit",
    "shadcn": "11", "IntersectionObserver": "12: fade-in on scroll", "mousemove": "13: cursor-following beam",
    "—": "16: em dash", "→": "arrow glyph", " · ": "middle-dot meta strings", "noise": "20: grain",
    "font-style: italic": "18: italic accents", "text-transform: uppercase": "all-caps labels",
}
BUZZWORDS = ["seamless", "supercharge", "revolutionize", "unlock", "empower", "next-gen", "cutting-edge", "game-changer",
             "leverage", "synergy", "effortless", "blazing", "magic"]
EMOJI = re.compile("[\U0001F300-\U0001FAFF☀-➿\U0001F000-\U0001F2FF]")


@pytest.mark.parametrize("name", sorted(ALL))
def test_no_banned_patterns(name):
    text = ALL[name]
    for pattern, why in BANNED.items():
        if pattern in ("https://", "http://") and name == "index.html":
            continue
        if pattern == "Inter" and name.endswith(".js"):
            text_check = re.search(r"font-family[^;]*Inter|['\"]Inter['\"]", text)
            assert not text_check, why
            continue
        assert pattern not in text, f"{name}: {pattern!r} ({why})"
    assert not EMOJI.search(text), f"{name}: emoji (3)"
    lowered = text.lower()
    for word in BUZZWORDS:
        assert not re.search(r"\b" + re.escape(word) + r"\b", lowered), f"{name}: buzzword {word!r} (17)"


def test_hover_never_fades_with_opacity():
    for block in re.findall(r":hover[^{]*\{([^}]*)\}", CSS):
        assert "opacity" not in block, "14: buttons fade on hover"


def test_spacing_comes_from_the_scale():
    """15: consistent spacing. Margins, paddings and gaps use the --s tokens (or 0/1px/2px/3px)."""
    for prop, value in re.findall(r"\b(padding[\w-]*|margin[\w-]*|gap)\s*:\s*([^;]+);", CSS):
        for part in value.replace("calc(", " ").replace(")", " ").split():
            ok = part.startswith("var(--s") or part in ("0", "auto", "1px", "2px", "3px", "-", "+") or part.startswith("var(--s")
            assert ok or part.endswith(","), f"{prop}: {value}"


def test_no_colored_left_border_cards():
    assert not re.search(r"border-left\s*:\s*\d+px\s+solid\s+var\(--(block|pause|go|action)", CSS), "5: colored border cards"


def _tokens(block: str) -> dict:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", block))


def _lum(hex_):
    c = [int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _contrast(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


PAIRS = [("ink", "paper"), ("ink", "surface"), ("muted", "paper"), ("muted", "surface"), ("action", "surface"),
         ("action", "paper"), ("action-ink", "action"), ("action-ink", "action-hover"), ("block", "block-tint"),
         ("pause", "pause-tint"), ("go", "go-tint"), ("block", "surface"), ("go", "paper"), ("pause", "paper"),
         ("paper", "ink"), ("ink", "pause-tint")]


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_text_contrast_meets_wcag_aa(scheme):
    """7: no low-contrast dark mode (or light mode)."""
    light = _tokens(CSS.split("@media (prefers-color-scheme: dark)")[0])
    dark = {**light, **_tokens(CSS.split("@media (prefers-color-scheme: dark)")[1].split("}")[0])}
    t = light if scheme == "light" else dark
    for fg, bg in PAIRS:
        ratio = _contrast(t[fg], t[bg])
        assert ratio >= 4.5, f"{scheme}: {fg} on {bg} is {ratio:.2f}:1"


def test_reduced_motion_and_focus_are_respected():
    assert "prefers-reduced-motion" in CSS and ":focus-visible" in CSS
