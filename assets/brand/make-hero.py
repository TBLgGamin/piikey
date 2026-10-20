"""Rebuilds docs/assets/hero-{light,dark}.png, the README's before/after picture.

Two ChatGPT-style windows: what you see on your screen, and what chatgpt.com actually receives.
Every text is real piikey output: the request is `piikey-cli anonymize` of MESSAGE, and YOU_SEE_REPLY
is `piikey-cli deanonymize --tolerant` of the reply in SITE_REPLY. Regenerate them together with a
fresh vault when you change the example, never edit one side by hand.

The page is drawn as HTML and photographed by Playwright with the installed Edge, at 2x, on a
transparent background so it sits on GitHub's light or dark page:
    python assets/brand/make-hero.py
"""

import base64
import html
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "docs" / "assets"
SYMBOL = HERE / "piikey-logo-kit" / "symbol" / "piikey-symbol-mono-{}.svg"

MESSAGE = (
    "My manager Mark Jansen (mark.jansen@example.nl) asked why I missed Monday's meeting. Can you help me "
    "write a short, friendly reply? My son had a fever and I had to pick him up from school. Sign it as "
    "Sanne de Vries, +31 6 12345678."
)
SITE_MESSAGE = (
    "My manager Kevin Wolters (geertje.young90@arrowholly.nl) asked why I missed Monday's meeting. Can you "
    "help me write a short, friendly reply? My son had a fever and I had to pick him up from school. Sign it "
    "as Nancy de Haas, +31 6 07420515."
)
SITE_REPLY = (
    "Hi Kevin,\n\nSorry for missing Monday's meeting. My son came down with a fever and I had to pick him up "
    "from school at short notice. I'll catch up on the notes today, and if anything needs my input, feel "
    "free to call me.\n\nBest regards,\nNancy de Haas\n+31 6 07420515"
)
YOU_SEE_REPLY = (
    "Hi Mark,\n\nSorry for missing Monday's meeting. My son came down with a fever and I had to pick him up "
    "from school at short notice. I'll catch up on the notes today, and if anything needs my input, feel "
    "free to call me.\n\nBest regards,\nSanne de Vries\n+31 6 12345678"
)
# Your value -> the stand-in piikey issued for it (longest first, so a full name wins over its first name).
PAIRS = [
    ("mark.jansen@example.nl", "geertje.young90@arrowholly.nl"),
    ("+31 6 12345678", "+31 6 07420515"),
    ("Sanne de Vries", "Nancy de Haas"),
    ("Mark Jansen", "Kevin Wolters"),
    ("Mark", "Kevin"),
]

THEMES = {
    "light": {
        "page_text": "#1f1f1f", "muted": "#6b6b78", "accent": "#6f49b1", "symbol": "6f49b1",
        "win": "#ffffff", "rail": "#f9f9f9", "border": "#e3e3e3", "bar": "#f3f3f3", "url": "#ffffff",
        "text": "#0d0d0d", "soft": "#5d5d5d", "bubble": "#f4f4f4", "composer": "#ffffff",
        "composer_border": "#e5e5e5", "send": "#0d0d0d", "send_fg": "#ffffff", "icon": "#8f8f8f",
        "mine": "rgba(0,0,0,0.07)", "mine_fg": "#0d0d0d", "proxy": "#ece4fb", "proxy_fg": "#5a37a0",
        "shadow": "0 18px 50px rgba(40,20,80,0.12), 0 2px 6px rgba(0,0,0,0.06)",
    },
    "dark": {
        "page_text": "#ecebef", "muted": "#a19cad", "accent": "#d6c9f9", "symbol": "d6c9f9",
        "win": "#000000", "rail": "#0b0b0b", "border": "#262626", "bar": "#141414", "url": "#1b1b1b",
        "text": "#ececec", "soft": "#b4b4b4", "bubble": "#1f1f1f", "composer": "#1b1b1b",
        "composer_border": "#1b1b1b", "send": "#5a5a5a", "send_fg": "#000000", "icon": "#8f8f8f",
        "mine": "rgba(255,255,255,0.10)", "mine_fg": "#ffffff", "proxy": "#3f3360", "proxy_fg": "#e2d8ff",
        "shadow": "0 18px 50px rgba(0,0,0,0.55), 0 0 0 1px #262626",
    },
}

ICONS = {  # small outline icons in the spirit of ChatGPT's collapsed sidebar
    "sidebar": '<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M9 4.5v15"/>',
    "edit": '<path d="M12 20h8"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    "search": '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
    "library": '<path d="M5 4v16M10 4v16"/><path d="m14.5 4.5 4.5 15"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "mic": '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5V21"/>',
    "up": '<path d="M12 19V6M6.5 11.5 12 6l5.5 5.5"/>',
    "copy": '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5"/>',
    "thumb": '<path d="M7.5 10.5v9h-3v-9ZM7.5 10.5 11 4c1.6 0 2.5 1 2.2 2.6l-.6 3.4h5.2a2 2 0 0 1 2 2.3l-1.1 5.6a2 2 0 0 1-2 1.6H7.5"/>',
    "lock": '<rect x="5.5" y="10.5" width="13" height="10" rx="2"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/>',
    "chevron": '<path d="m7 10 5 5 5-5"/>',
}


def icon(name: str, size: int = 20) -> str:
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</svg>'
    )


def marked(text: str, side: int) -> str:
    """HTML of `text` with every value of `side` (0 = yours, 1 = stand-in) in a pill."""
    values = sorted({pair[side] for pair in PAIRS}, key=len, reverse=True)
    out, i = [], 0
    while i < len(text):
        hit = next(
            (v for v in values if text.startswith(v, i) and not (i + len(v) < len(text) and text[i + len(v)].isalpha())),
            None,
        )
        if hit:
            out.append(f'<span class="v{side}">{html.escape(hit)}</span>')
            i += len(hit)
        else:
            out.append(html.escape(text[i]))
            i += 1
    return "".join(out).replace("\n", "<br>")


def window(side: int) -> str:
    message, reply = (MESSAGE, YOU_SEE_REPLY) if side == 0 else (SITE_MESSAGE, SITE_REPLY)
    rail = "".join(f'<div class="ri">{icon(n)}</div>' for n in ("sidebar", "edit", "search", "library"))
    return f"""
<div class="win">
  <div class="bar"><div class="url">{icon("lock", 13)}<span>chatgpt.com</span></div></div>
  <div class="app">
    <div class="rail">{rail}<div class="avatar">S</div></div>
    <div class="main">
      <div class="top">ChatGPT {icon("chevron", 16)}</div>
      <div class="thread">
        <div class="user"><div class="bubble">{marked(message, side)}</div></div>
        <div class="reply">{marked(reply, side)}</div>
        <div class="acts">{icon("copy", 17)}{icon("thumb", 17)}</div>
      </div>
      <div class="composer">
        <span class="ci">{icon("plus")}</span><span class="ph">Ask anything</span>
        <span class="ci">{icon("mic")}</span><span class="send">{icon("up", 18)}</span>
      </div>
    </div>
  </div>
</div>"""


def page(theme: dict) -> str:
    symbol = base64.b64encode(Path(str(SYMBOL).format(theme["symbol"])).read_bytes()).decode()
    t = theme
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
* {{ box-sizing: border-box; margin: 0; }}
html, body {{ background: transparent; }}
body {{ font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif; color: {t["page_text"]}; }}
#stage {{ width: 1600px; padding: 36px 40px 30px; }}
.cols {{ display: grid; grid-template-columns: 1fr 170px 1fr; align-items: stretch; }}
.label {{ font: 700 14px "Segoe UI", sans-serif; letter-spacing: .08em; text-transform: uppercase;
  color: {t["muted"]}; margin: 0 0 14px 6px; }}
.label.site {{ color: {t["accent"]}; }}
.win {{ background: {t["win"]}; border-radius: 16px; overflow: hidden; box-shadow: {t["shadow"]};
  border: 1px solid {t["border"]}; height: 640px; display: flex; flex-direction: column; }}
.bar {{ height: 44px; background: {t["bar"]}; display: flex; align-items: center; padding: 0 14px;
  border-bottom: 1px solid {t["border"]}; }}
.url {{ display: flex; align-items: center; gap: 7px; background: {t["url"]}; color: {t["soft"]};
  font-size: 13px; padding: 5px 14px; border-radius: 999px; width: 100%; }}
.app {{ flex: 1; display: flex; min-height: 0; }}
.rail {{ width: 52px; background: {t["rail"]}; border-right: 1px solid {t["border"]}; display: flex;
  flex-direction: column; align-items: center; padding-top: 12px; gap: 6px; color: {t["icon"]}; }}
.ri {{ width: 36px; height: 36px; display: grid; place-items: center; border-radius: 8px; }}
.avatar {{ margin-top: auto; margin-bottom: 14px; width: 28px; height: 28px; border-radius: 50%;
  background: #e8a0c8; color: #3a1530; font-size: 12px; font-weight: 600; display: grid; place-items: center; }}
.main {{ flex: 1; display: flex; flex-direction: column; min-width: 0; color: {t["text"]}; }}
.top {{ height: 52px; display: flex; align-items: center; gap: 4px; padding: 0 18px; font-size: 18px; }}
.top svg {{ color: {t["icon"]}; }}
.thread {{ flex: 1; padding: 6px 30px 0; font-size: 15.5px; line-height: 1.62; overflow: hidden; }}
.user {{ display: flex; justify-content: flex-end; margin-bottom: 20px; }}
.bubble {{ background: {t["bubble"]}; border-radius: 22px; padding: 11px 18px; max-width: 86%; }}
.reply {{ margin-right: 10px; }}
.acts {{ display: flex; gap: 14px; color: {t["icon"]}; margin-top: 10px; }}
.composer {{ margin: 0 22px 22px; height: 54px; border-radius: 28px; background: {t["composer"]};
  border: 1px solid {t["composer_border"]}; display: flex; align-items: center; gap: 12px; padding: 0 10px 0 16px;
  box-shadow: 0 2px 10px rgba(0,0,0,.05); }}
.ci {{ color: {t["icon"]}; display: grid; }}
.ph {{ flex: 1; color: {t["icon"]}; font-size: 15.5px; }}
.send {{ width: 36px; height: 36px; border-radius: 50%; background: {t["send"]}; color: {t["send_fg"]};
  display: grid; place-items: center; }}
.v0, .v1 {{ border-radius: 6px; padding: 1px 5px; margin: 0 -1px; -webkit-box-decoration-break: clone; }}
.v0 {{ background: {t["mine"]}; color: {t["mine_fg"]}; font-weight: 600; }}
.v1 {{ background: {t["proxy"]}; color: {t["proxy_fg"]}; font-weight: 600; }}
.mid {{ display: flex; align-items: center; justify-content: center; position: relative; padding-top: 30px; }}
.mid .line {{ position: absolute; left: 14px; right: 14px; top: calc(50% + 15px); height: 2px; background: {t["accent"]}; opacity: .55; }}
.mid .tip {{ position: absolute; right: 8px; top: calc(50% + 9px); width: 0; height: 0;
  border-left: 12px solid {t["accent"]}; border-top: 7px solid transparent; border-bottom: 7px solid transparent; opacity: .8; }}
.key {{ position: relative; width: 84px; height: 84px; border-radius: 50%; background: {t["win"]};
  border: 2.5px solid {t["accent"]}; display: grid; place-items: center; box-shadow: {t["shadow"]}; }}
.key img {{ width: 46px; height: 46px; }}
.caption {{ text-align: center; color: {t["muted"]}; font-size: 16px; margin-top: 26px; }}
</style></head><body><div id="stage">
  <div class="cols">
    <div><div class="label">On your screen</div>{window(0)}</div>
    <div class="mid"><div class="line"></div><div class="tip"></div>
      <div class="key"><img src="data:image/svg+xml;base64,{symbol}" alt=""></div></div>
    <div><div class="label site">What chatgpt.com sees</div>{window(1)}</div>
  </div>
  <div class="caption">Real piikey output. The site only ever gets the stand-ins; its reply is turned back into your values before you see it.</div>
</div></body></html>"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        for name, theme in THEMES.items():
            tab = browser.new_page(viewport={"width": 1600, "height": 900}, device_scale_factor=2)
            tab.set_content(page(theme))
            tab.wait_for_load_state("networkidle")
            out = OUT / f"hero-{name}.png"
            tab.locator("#stage").screenshot(path=str(out), omit_background=True)
            print(f"wrote {out}")
        browser.close()


if __name__ == "__main__":
    main()
