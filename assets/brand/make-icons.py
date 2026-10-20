"""Builds app/assets/piikey.ico from the brand kit's 1024 px app icon (run: python assets/brand/make-icons.py; needs Pillow)."""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "piikey-logo-kit" / "symbol" / "piikey-symbol-app-icon-1024.png"
TARGET = ROOT.parent.parent / "app" / "assets" / "piikey.ico"

# Tray (16..24), title bar (16..32), taskbar and DPI scales (32..64), Explorer (256).
SIZES = (16, 20, 24, 32, 40, 48, 64, 256)


def main() -> None:
    source = Image.open(SOURCE).convert("RGBA")
    # Pillow resamples RGBA premultiplied, so the transparent corners stay clean.
    frames = [source.resize((size, size), Image.Resampling.LANCZOS) for size in SIZES]
    frames[-1].save(
        TARGET,
        format="ICO",
        sizes=[frame.size for frame in frames],
        append_images=frames[:-1],
    )
    print(f"wrote {TARGET} ({TARGET.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
