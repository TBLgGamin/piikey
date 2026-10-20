"""Rebuilds assets/brand/social-preview.png, the GitHub social preview (1280x640).

White horizontal logo and the tagline on piikey purple. Run from anywhere:
    python assets/brand/make-social-preview.py
Upload the result in the repository settings (General > Social preview).
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
LOGO = HERE / "piikey-logo-kit" / "horizontal" / "piikey-horizontal-white-1200.png"
OUT = HERE / "social-preview.png"
FONT = Path(r"C:\Windows\Fonts\segoeui.ttf")

SIZE = (1280, 640)
PURPLE = "#6f49b1"
LOGO_WIDTH = 560
LOGO_TOP = 190
TAGLINE = "Your personal data stays on your PC. AI gets believable stand-ins."
TAGLINE_SIZE = 40
TAGLINE_TOP = 450


def main() -> None:
    canvas = Image.new("RGB", SIZE, PURPLE)
    logo = Image.open(LOGO).convert("RGBA")
    height = round(logo.height * LOGO_WIDTH / logo.width)
    logo = logo.resize((LOGO_WIDTH, height), Image.Resampling.LANCZOS)
    canvas.paste(logo, ((SIZE[0] - LOGO_WIDTH) // 2, LOGO_TOP), logo)

    draw = ImageDraw.Draw(canvas)
    font = ImageFont.truetype(str(FONT), TAGLINE_SIZE)
    left, _, right, _ = draw.textbbox((0, 0), TAGLINE, font=font)
    draw.text(((SIZE[0] - (right - left)) // 2 - left, TAGLINE_TOP), TAGLINE, font=font, fill="white")

    canvas.save(OUT, optimize=True)
    print(f"wrote {OUT.relative_to(HERE.parent.parent)}")


if __name__ == "__main__":
    main()
