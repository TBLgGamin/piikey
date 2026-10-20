"""Rebuilds docs/assets/hero-{light,dark}.png, the README's before/after card.

Left: a message as you type it, your values marked. Right: what the site receives, each value
swapped for piikey's stand-in. The text is real `piikey-cli anonymize` output; keep it that way
when you change it. Transparent background, so it sits on GitHub's light or dark page.
    python assets/brand/make-hero.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "docs" / "assets"
FONTS = Path(r"C:\Windows\Fonts")
SYMBOL = HERE / "piikey-logo-kit" / "symbol" / "piikey-symbol-mono-{}-512.png"

# (text, stand-in or None): plain text has None.
MESSAGE = [
    ("Hi, I'm ", None),
    ("Sanne de Vries", "Eline de Deruiter"),
    (" (", None),
    ("sanne.devries@example.nl", "carolyn.carter38@olivedawn.nl"),
    (", ", None),
    ("+31 6 12345678", "+31 6 48171596"),
    ("). Please refund €250 to ", None),
    ("NL91ABNA0417164300", "NL69ABNA4201013737"),
    (": my card ", None),
    ("4111 1111 1111 1111", "4493 2819 7493 4301"),
    (" was charged twice. I live at ", None),
    ("Keizersgracht 123, 1015 CJ Amsterdam", "Crimsonvia 634, 4351 CJ Pinecliff"),
    (".", None),
]

THEMES = {
    "light": {
        "card": "#ffffff", "border": "#e4dff0", "text": "#1f1f1f", "muted": "#6b6b78",
        "own_bg": "#f1eff4", "own_fg": "#1f1f1f", "proxy_bg": "#ece4fb", "proxy_fg": "#5a37a0",
        "accent": "#6f49b1", "symbol": "6f49b1",
    },
    "dark": {
        "card": "#26232d", "border": "#3a3545", "text": "#ecebef", "muted": "#a19cad",
        "own_bg": "#3a3742", "own_fg": "#ecebef", "proxy_bg": "#3f3360", "proxy_fg": "#d6c9f9",
        "accent": "#d6c9f9", "symbol": "d6c9f9",
    },
}

S = 2  # drawn at 2x for sharp text on high-DPI screens
W, H = 1600 * S, 450 * S
CARD_W, CARD_TOP, CARD_H = 660 * S, 40 * S, 330 * S
PAD = 36 * S
GAP = W - 2 * CARD_W - 2 * 40 * S  # the space between the cards, for the key and the arrow
FONT = ImageFont.truetype(str(FONTS / "segoeui.ttf"), 25 * S)
FONT_SB = ImageFont.truetype(str(FONTS / "segoeuisl.ttf"), 25 * S)
LABEL = ImageFont.truetype(str(FONTS / "segoeuib.ttf"), 17 * S)
CAPTION = ImageFont.truetype(str(FONTS / "segoeui.ttf"), 19 * S)
LINE = 44 * S
PILL_X = 7 * S


def tokens(side: int):
    """(word, marked) pieces; a marked value stays one piece so its pill is never split."""
    for text, proxy in MESSAGE:
        if proxy is None:
            for i, word in enumerate(text.split(" ")):
                yield ((" " if i else "") + word, False)
        else:
            yield ((text, proxy)[side], True)


def card(draw: ImageDraw.ImageDraw, x: int, side: int, theme: dict, label: str) -> None:
    draw.rounded_rectangle(
        (x, CARD_TOP, x + CARD_W, CARD_TOP + CARD_H), 22 * S, fill=theme["card"], outline=theme["border"], width=2 * S
    )
    color = theme["accent"] if side else theme["muted"]
    draw.text((x + PAD, CARD_TOP + PAD - 6 * S), label.upper(), font=LABEL, fill=color)
    cx, cy = x + PAD, CARD_TOP + PAD + 40 * S
    right = x + CARD_W - PAD
    bg, fg = (theme["proxy_bg"], theme["proxy_fg"]) if side else (theme["own_bg"], theme["own_fg"])
    for piece, marked in tokens(side):
        font = FONT_SB if marked else FONT
        width = draw.textlength(piece, font=font) + (2 * PILL_X if marked else 0)
        if cx + width > right:
            cx, cy = x + PAD, cy + LINE
            piece = piece.lstrip()
            width = draw.textlength(piece, font=font) + (2 * PILL_X if marked else 0)
        if marked:
            cx += 2 * S  # breathing room between a pill and the text before it
            top = cy + 5 * S
            draw.rounded_rectangle(
                (cx, top, cx + draw.textlength(piece, font=font) + 2 * PILL_X, top + 34 * S), 8 * S, fill=bg
            )
            draw.text((cx + PILL_X, cy), piece, font=font, fill=fg)
            cx += draw.textlength(piece, font=font) + 2 * PILL_X
        else:
            draw.text((cx, cy), piece, font=font, fill=theme["text"])
            cx += width


def middle(canvas: Image.Image, draw: ImageDraw.ImageDraw, theme: dict) -> None:
    mid_x, mid_y = W // 2, CARD_TOP + CARD_H // 2
    r = 46 * S
    draw.ellipse((mid_x - r, mid_y - r, mid_x + r, mid_y + r), fill=theme["card"], outline=theme["accent"], width=3 * S)
    symbol = Image.open(str(SYMBOL).format(theme["symbol"])).convert("RGBA")
    size = int(r * 1.15)
    symbol = symbol.resize((size, size), Image.Resampling.LANCZOS)
    canvas.paste(symbol, (mid_x - size // 2, mid_y - size // 2), symbol)
    for sign in (-1, 1):  # short arrow stems on both sides of the key, pointing right
        start = mid_x + sign * (r + 10 * S)
        end = mid_x + sign * (GAP // 2 - 8 * S)
        a, b = sorted((start, end))
        draw.line((a, mid_y, b, mid_y), fill=theme["accent"], width=3 * S)
    tip = mid_x + GAP // 2 - 8 * S
    draw.polygon([(tip, mid_y), (tip - 12 * S, mid_y - 9 * S), (tip - 12 * S, mid_y + 9 * S)], fill=theme["accent"])


def render(name: str, theme: dict) -> None:
    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    left = 40 * S
    card(draw, left, 0, theme, "You type")
    card(draw, W - left - CARD_W, 1, theme, "The internet sees")
    middle(canvas, draw, theme)
    caption = "Same shape, still valid: the IBAN passes mod-97, the card passes Luhn. The reply comes back with your real values."
    width = draw.textlength(caption, font=CAPTION)
    draw.text(((W - width) // 2, CARD_TOP + CARD_H + 22 * S), caption, font=CAPTION, fill=theme["muted"])
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"hero-{name}.png"
    canvas.save(out, optimize=True)
    print(f"wrote {out}")


if __name__ == "__main__":
    for name, theme in THEMES.items():
        render(name, theme)
