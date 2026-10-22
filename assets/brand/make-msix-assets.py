"""Rebuilds packaging/windows/msix/Assets/*.png, the MSIX package's logos, from the brand kit.

Run from anywhere (needs Pillow):
    python assets/brand/make-msix-assets.py

What Windows asks for, and which kit file answers it (see piikey-logo-kit/README.md):
- Tiles, the Store logo and the plated app-list icon: the light-mode app icon (white key on
  #6f49b1, rounded corners), also the plate colour that AppxManifest.xml names.
- The taskbar and Start icon without a plate (`altform-unplated` on a dark theme,
  `altform-lightunplated` on a light one): the key alone, lilac #d6c9f9 for dark backgrounds and
  purple #6f49b1 for light ones. Below 32 px it is the small-size cut (heavier stem, one tooth).
"""

from pathlib import Path

from PIL import Image

KIT = Path(__file__).resolve().parent / "piikey-logo-kit" / "symbol"
OUT = Path(__file__).resolve().parents[2] / "packaging" / "windows" / "msix" / "Assets"

APP_ICON = KIT / "piikey-symbol-app-icon-1024.png"
KEY_PURPLE = KIT / "piikey-symbol-mono-6f49b1-1024.png"
KEY_LILAC = KIT / "piikey-symbol-mono-d6c9f9-1024.png"
# The small-size cut; the kit ships it in black only, so its alpha channel is recoloured.
KEY_SMALL = KIT / "piikey-symbol-favicon-1024.png"

PURPLE = (0x6F, 0x49, 0xB1, 255)
LILAC = (0xD6, 0xC9, 0xF9, 255)

# Windows picks the file for the display scale (100% is the unqualified size).
SCALES = (100, 125, 150, 200, 400)
# The sizes the taskbar, the Start menu, Alt+Tab and Explorer ask the 44 px icon for.
TARGET_SIZES = (16, 24, 32, 48, 256)
# The kit's own guidance: the small cut below this size.
SMALL_CUT_BELOW = 32
# The key leaves this much of the canvas free, so it does not touch the taskbar button's edge.
KEY_FILL = 0.92

# (file name, base size in px at 100%)
LOGOS = (("Square44x44Logo", 44), ("Square150x150Logo", 150), ("StoreLogo", 50))


def resized(image: Image.Image, size: int) -> Image.Image:
    # Pillow resamples RGBA premultiplied, so the transparent corners stay clean.
    return image.resize((size, size), Image.Resampling.LANCZOS)


def key_on_canvas(mask_source: Path, colour: tuple[int, int, int, int], size: int) -> Image.Image:
    """The key alone, `colour` on transparent, as large as KEY_FILL of a size x size canvas allows."""
    mask = Image.open(mask_source).convert("RGBA").getchannel("A")
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


def save(image: Image.Image, name: str) -> None:
    path = OUT / name
    image.save(path, format="PNG", optimize=True)
    print(f"wrote {path.relative_to(OUT.parents[3])} ({image.width}x{image.height})")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.png"):
        stale.unlink()
    tile = Image.open(APP_ICON).convert("RGBA")

    for name, base in LOGOS:
        # The unqualified file is what the manifest names, and what makeappx checks for.
        save(resized(tile, base), f"{name}.png")
        for scale in SCALES:
            save(resized(tile, (base * scale + 50) // 100), f"{name}.scale-{scale}.png")

    for size in TARGET_SIZES:
        save(resized(tile, size), f"Square44x44Logo.targetsize-{size}.png")
        for suffix, regular, colour in (
            ("altform-unplated", KEY_LILAC, LILAC),
            ("altform-lightunplated", KEY_PURPLE, PURPLE),
        ):
            source = KEY_SMALL if size < SMALL_CUT_BELOW else regular
            save(
                key_on_canvas(source, colour, size),
                f"Square44x44Logo.targetsize-{size}_{suffix}.png",
            )


if __name__ == "__main__":
    main()
