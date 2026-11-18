# Reverso brand

## Mark

The mark is a gold hexagon with a reverse chevron, dissolving into its own
bytes on the right half. Left half: the binary, intact. Right half: the same
binary, taken apart. One accent (Signal Gold), one ink (Reverso Ink).

## Files

| File | Use |
| --- | --- |
| `assets/logo/symbol-tile.svg` | Primary mark. Tile master, self-contained on any background |
| `assets/logo/symbol.svg` | Transparent mark, full colour (gold hex, ink chevron), for dark backgrounds |
| `assets/logo/symbol-ink.svg` | One-colour ink mark (chevron cut out). Use on light backgrounds |
| `assets/logo/symbol-gold.svg` | One-colour gold mark, for dark backgrounds |
| `assets/logo/symbol-white.svg` | One-colour white mark, for ink or photographic backgrounds |
| `assets/logo/symbol-tile-small.svg` | Small-size cut: two byte columns, bolder cells, for 16-32 px |
| `assets/logo/symbol-square.svg` | Avatar / social tile master |
| `assets/logo/app-icon.svg` | App icon (white mark on ink tile) |
| `assets/logo/lockup-horizontal.svg` | Mark plus wordmark, horizontal (light backgrounds) |
| `assets/logo/lockup-horizontal-reversed.svg` | Mark plus wordmark, horizontal (dark backgrounds) |
| `assets/logo/lockup-stacked.svg` | Mark above wordmark, stacked (light backgrounds) |
| `assets/logo/lockup-stacked-reversed.svg` | Mark above wordmark, stacked (dark backgrounds) |
| `assets/logo/favicon.ico`, `favicon.svg`, `favicon-16/32/48.png` | Browser tab icons |
| `assets/logo/icon-192.png`, `icon-512.png`, `maskable-512.png` | Web app icons |
| `assets/logo/apple-touch-icon.png` | iOS touch icon |
| `assets/logo/site.webmanifest`, `head-snippet.html` | PWA wiring for the website |

## Clear space

Keep a clear space equal to the byte cell size (`26` units in the `512`
canvas) on all sides. For the tile mark this is built into the artwork.

## Minimum sizes

- Tile mark: 32 px
- Mark only (transparent): 24 px
- Horizontal lockup: 140 px wide
- Below minimum size, use `symbol-tile-small.svg`

## Colour

| Role | Value |
| --- | --- |
| Reverso Ink (tile, chevron, mono mark) | `#101E26` |
| Signal Gold (hex, bytes, accents) | `#F4C430` |

Gold is used for the hexagon and the byte cells only, never for body text on
white. Mono print: use `symbol-ink.svg` on light stock, `symbol-white.svg` on
dark stock. Do not recolour the gold.

## Typography

The wordmark is the same rectilinear slab family used across Reverso's media.
Do not re-typeset "REVERSO" in a stock font as a substitute. Use the shipped
lockup files.

## Do not

- Do not rotate, shear, outline, shadow or gradient the mark
- Do not stretch it non-proportionally
- Do not place the transparent gold mark on light backgrounds
- Do not add strokes or outlines to the hexagon or the bytes
- Do not re-set the wordmark in another face
