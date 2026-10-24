"""Builds the app's icon files in app/assets/ from the brand kit (run: python assets/brand/make-icons.py; needs Pillow).

- piikey.ico: the app icon (white key on the purple tile), 1024 px app icon scaled to every shell size.
  It is also the tray icon while protection is on.
- tray-off.ico: the tray icon while piikey is off: the key alone in a neutral grey, no tile, so it reads
  on a light and a dark taskbar alike.
- tray-attention.ico: the tray icon while piikey needs you (a missing certificate, a failed model): the
  app icon with an amber dot.
"""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
KIT = ROOT / "piikey-logo-kit" / "symbol"
SOURCE = KIT / "piikey-symbol-app-icon-1024.png"
# The key alone on transparent; the kit ships the small-size cut (heavier stem) in black only.
KEY = KIT / "piikey-symbol-mono-6f49b1-1024.png"
KEY_SMALL = KIT / "piikey-symbol-favicon-1024.png"
ASSETS = ROOT.parent.parent / "app" / "assets"

# Tray (16..24), title bar (16..32), taskbar and DPI scales (32..64), Explorer (256).
SIZES = (16, 20, 24, 32, 40, 48, 64, 256)
# The tray icons are never asked for more than the largest notification-area scale.
TRAY_SIZES = (16, 20, 24, 32, 40, 48, 64)

GREY = (0x8E, 0x8E, 0x93, 255)
AMBER = (0xF5, 0xA6, 0x23, 255)
RING = (0xFF, 0xFF, 0xFF, 255)
# Below this size the kit's own guidance is the small cut of the key.
SMALL_CUT_BELOW = 32
# The key leaves this much of the canvas free.
KEY_FILL = 0.94


def save_ico(frames: dict[int, Image.Image], name: str) -> None:
    sizes = sorted(frames)
    target = ASSETS / name
    # Pillow wants the largest frame as the image and the rest appended.
    frames[sizes[-1]].save(
        target,
        format="ICO",
        sizes=[frames[size].size for size in sizes],
        append_images=[frames[size] for size in sizes[:-1]],
    )
    print(f"wrote {target} ({target.stat().st_size} bytes)")


def resized(image: Image.Image, size: int) -> Image.Image:
    # Pillow resamples RGBA premultiplied, so the transparent corners stay clean.
    return image.resize((size, size), Image.Resampling.LANCZOS)


def with_dot(tile: Image.Image) -> Image.Image:
    """The tile with an amber dot ringed in white at its lower right, drawn large so it scales cleanly."""
    image = tile.copy()
    side = image.width
    centre = round(side * 0.77)
    radius = round(side * 0.22)
    ring = round(side * 0.06)
    draw = ImageDraw.Draw(image)
    draw.ellipse(
        (centre - radius - ring, centre - radius - ring, centre + radius + ring, centre + radius + ring),
        fill=RING,
    )
    draw.ellipse((centre - radius, centre - radius, centre + radius, centre + radius), fill=AMBER)
    return image


def key_on_canvas(source: Path, colour: tuple[int, int, int, int], size: int) -> Image.Image:
    """The key alone, `colour` on transparent, as large as KEY_FILL of a size x size canvas allows."""
    mask = Image.open(source).convert("RGBA").getchannel("A")
    key = Image.new("RGBA", mask.size, colour)
    key.putalpha(mask)
    key = key.crop(mask.getbbox())
    scale = KEY_FILL * size / max(key.size)
    key = key.resize(
        (max(1, round(key.width * scale)), max(1, round(key.height * scale))),
        Image.Resampling.LANCZOS,
    )
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(key, ((size - key.width) // 2, (size - key.height) // 2), key)
    return canvas


def main() -> None:
    tile = Image.open(SOURCE).convert("RGBA")
    save_ico({size: resized(tile, size) for size in SIZES}, "piikey.ico")

    dotted = with_dot(tile)
    save_ico({size: resized(dotted, size) for size in TRAY_SIZES}, "tray-attention.ico")

    save_ico(
        {
            size: key_on_canvas(KEY_SMALL if size < SMALL_CUT_BELOW else KEY, GREY, size)
            for size in TRAY_SIZES
        },
        "tray-off.ico",
    )


if __name__ == "__main__":
    main()
