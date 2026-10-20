# piikey logo kit

A lowercase **p** drawn as a key: ring bow, shaft stem, two bit teeth. The wordmark is custom monoline lettering built on the same rounded stroke, so the key and the name share one construction.

## Colour

| Use | HEX | RGB |
|---|---|---|
| piikey purple, **light mode** (on white / light backgrounds) | `#6f49b1` | 111, 73, 177 |
| piikey lilac, **dark mode** (on dark backgrounds) | `#d6c9f9` | 214, 201, 249 |
| White | `#FFFFFF` | 255, 255, 255 |
| Black | `#000000` | 0, 0, 0 |

White on `#6f49b1` is about 6:1; `#6f49b1` on `#d6c9f9` is about 4.7:1 (both pass WCAG AA). CMYK and Pantone values are not specified: have your printer match from a proof.

The logo is one colour only: purple on light, lilac on dark, or black/white. No gradients, shadows or outlines.

`web-icons/favicon.svg` switches between the two purples with `prefers-color-scheme`. The PNG favicons and `.ico` use `#6f49b1`.

## Which file do I use?

| Need | File |
|---|---|
| Website header, docs, slides (light mode) | `horizontal/piikey-horizontal-mono-6f49b1.svg` |
| Same in dark mode | `horizontal/piikey-horizontal-mono-d6c9f9.svg` |
| Over a photo or other colour | `horizontal/piikey-horizontal-white.svg` or `-black.svg` |
| Square or narrow spaces, posters | `stacked/piikey-stacked-*.svg` |
| Name only, no symbol | `wordmark/piikey-wordmark-*.svg` |
| Avatar, social profile, GitHub org | `symbol/piikey-symbol-square-*.png` |
| App icon, light mode | `symbol/piikey-symbol-app-icon.svg` / `-1024.png` (white key on `#6f49b1`) |
| App icon, dark mode | `symbol/piikey-symbol-dark-app-icon.svg` / `-1024.png` (`#6f49b1` key on `#d6c9f9`) |
| Browser tab, PWA, home screen | `web-icons/` (see `head-snippet.html`) |
| Print, engraving, stamps, one ink | `*-black.svg` |
| Anything under 32 px | `symbol/piikey-symbol-small.svg` |

Every lockup folder holds `black`, `white`, `mono-6f49b1` (light mode) and `mono-d6c9f9` (dark mode) as SVG, plus transparent PNGs at 600 / 1200 / 2400 px wide. Symbol PNGs are 64 / 256 / 512 / 1024.

`master/` holds the source SVGs (single colour, outlined shapes, no live text, no effects). Edit those, never the exports.

## Size and space

- Clear space: half the x-height of the wordmark (the height of the "e") on all sides of any version.
- Minimum width: horizontal 96 px / 25 mm; stacked 64 px / 18 mm; symbol 16 px / 5 mm.
- Below 32 px use `piikey-symbol-small.svg` (heavier stem, one tooth). The favicon and web icons already use it.
- Symbol-only works once the name is nearby or the product is known. Otherwise use a lockup.

## Don't

- Don't stretch, rotate, recolour outside the colours above, or add effects.
- Don't retype the name in a font, or change the lockup spacing.
- Don't use the purple on dark backgrounds or the lilac on light ones; switch to the matching mode colour.
- Don't put either purple on a mid-tone or busy background; use white or black.
- Don't use the symbol's teeth as separate decoration.

## Web

Copy `web-icons/` to your site root and paste `head-snippet.html` into `<head>`. `site.webmanifest` includes 192/512 and a maskable icon on the purple tile.

## Caveats

- Not trademark-checked. Run a trademark and reverse-image search before committing to it.
- The wordmark is custom-drawn paths, so there are no font licences to manage.
- The symbol is a p-shaped key, so it also reads as the letter p alone. That is intended.
