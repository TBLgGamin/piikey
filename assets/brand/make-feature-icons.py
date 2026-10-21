"""Rebuilds the README feature icons: docs/assets/icons/{light,dark}/<name>.svg.

24x24 stroke icons (stroke-width 1.75, round caps and joins, no fill) in the piikey purple
for light themes and the pale purple for dark themes. Run from anywhere:
    python assets/brand/make-feature-icons.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "docs" / "assets" / "icons"

STROKES = {"light": "#6f49b1", "dark": "#d6c9f9"}

# One entry per icon: the SVG child elements, drawn on a 24x24 grid.
ICONS = {
    # mask over a speech bubble
    "mask": [
        '<path d="M4 3.5h16a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5h-8l-4 4v-4H4A1.5 1.5 0 0 1 2.5 15V5A1.5 1.5 0 0 1 4 3.5z"/>',
        '<path d="M6 8c2-1 4-1 6 0 2-1 4-1 6 0v2.5c0 1.2-1 2-2.2 2-1.3 0-2-.8-2.8-1.5-.8.7-1.5 1.5-2.8 1.5C7 12.5 6 11.7 6 10.5z"/>',
    ],
    # text field with an outline
    "highlight": [
        '<rect x="2" y="4" width="20" height="16" rx="3" stroke-dasharray="3.2 2.6"/>',
        '<rect x="6" y="8.5" width="12" height="7" rx="1.5"/>',
        '<path d="M9.5 10.8v2.4"/>',
    ],
    # folder with a magnifier
    "explorer": [
        '<path d="M3 17V7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v2"/>',
        '<path d="M3 17a2 2 0 0 0 2 2h5"/>',
        '<circle cx="16" cy="16" r="3.5"/>',
        '<path d="M18.6 18.6 21.5 21.5"/>',
    ],
    # treemap: rectangles of different sizes
    "inventory": [
        '<rect x="3" y="3" width="18" height="18" rx="2"/>',
        '<path d="M12 3v18"/>',
        '<path d="M12 10h9"/>',
        '<path d="M3 14h9"/>',
        '<path d="M16.5 10v11"/>',
    ],
    # person with a magnifier
    "subject": [
        '<circle cx="10" cy="8" r="3.5"/>',
        '<path d="M3 20c0-3.5 3-6 7-6 1 0 1.8.1 2.6.4"/>',
        '<circle cx="17" cy="16" r="3"/>',
        '<path d="M19.2 18.2 21.5 20.5"/>',
    ],
    # safe
    "vault": [
        '<rect x="3" y="4" width="18" height="15" rx="2"/>',
        '<path d="M7 19v2"/>',
        '<path d="M17 19v2"/>',
        '<circle cx="12" cy="11.5" r="3.5"/>',
        '<path d="M12 11.5h2"/>',
    ],
    # braces { }
    "api": [
        '<path d="M8 4c-2 0-3 1-3 3v2c0 1.5-.8 3-2 3 1.2 0 2 1.5 2 3v2c0 2 1 3 3 3"/>',
        '<path d="M16 4c2 0 3 1 3 3v2c0 1.5.8 3 2 3-1.2 0-2 1.5-2 3v2c0 2-1 3-3 3"/>',
    ],
    # prompt >_
    "terminal": [
        '<rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/>',
        '<path d="M7 10l3 2.5L7 15"/>',
        '<path d="M12.5 15.5H17"/>',
    ],
    # stacked pages
    "documents": [
        '<rect x="4" y="7" width="13" height="14" rx="2"/>',
        '<path d="M8 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-1"/>',
        '<path d="M7.5 12h6"/>',
        '<path d="M7.5 15.5h6"/>',
    ],
    # chip
    "model": [
        '<rect x="6" y="6" width="12" height="12" rx="2"/>',
        '<rect x="9.5" y="9.5" width="5" height="5" rx="1"/>',
        '<path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/>',
    ],
    # house with a shield
    "local": [
        '<path d="M3 11.5 12 4l9 7.5"/>',
        '<path d="M5 10.5V21h14V10.5"/>',
        '<path d="M12 11l3.5 1.3v3.2c0 2.2-1.6 3.6-3.5 4.5-1.9-.9-3.5-2.3-3.5-4.5v-3.2z"/>',
    ],
}


def svg(stroke: str, shapes: list[str]) -> str:
    body = "\n".join(f"  {shape}" for shape in shapes)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" '
        f'fill="none" stroke="{stroke}" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round">\n{body}\n</svg>\n'
    )


def main() -> None:
    for variant, stroke in STROKES.items():
        folder = OUT / variant
        folder.mkdir(parents=True, exist_ok=True)
        for name, shapes in ICONS.items():
            (folder / f"{name}.svg").write_text(svg(stroke, shapes), encoding="utf-8", newline="\n")
    print(f"wrote {len(ICONS) * len(STROKES)} icons to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
