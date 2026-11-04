# py8dis logo

The mark is the digit 8 drawn on an 8×8 pixel grid, the way 8-bit machines store their fonts, with the eight bytes that make it up (`3C 66 66 3C 66 66 3C 00`) beside it.

## Files

| File | Use |
|---|---|
| `py8dis-banner-slim.svg` | 1280×260 strip on blue, used at the top of the main README |
| `py8dis-banner.svg` / `.png` | 1280×640 banner on blue, for the GitHub social preview |
| `py8dis-logo-on-light.svg` | Full logo, transparent background, for light pages |
| `py8dis-logo-on-dark.svg` | Full logo, transparent background, for dark pages |
| `py8dis-mark.svg` | Square app icon: white 8 on a blue rounded tile |
| `py8dis-icon-512.png`, `apple-touch-icon.png` | The mark at 512px and 180px |
| `favicon.ico`, `favicon-16.png`, `favicon-32.png`, `favicon-48.png` | Favicons, drawn so each glyph pixel lands on whole screen pixels |

The text in the SVGs is converted to outlines, so they don't need the font installed.

## Colours

| | Hex |
|---|---|
| Electric blue (background) | `#1F4BFF` |
| White (glyph, wordmark) | `#FFFFFF` |
| Pale blue (hex bytes, tagline) | `#E0E6FF` |
| Grid dots | `#3A62FF` |

Typeface: IBM Plex Mono (SemiBold for the wordmark, Regular for the rest).

## Using it in a README

To switch between the light and dark versions automatically on GitHub:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo/py8dis-logo-on-dark.svg">
  <img alt="py8dis" src="docs/logo/py8dis-logo-on-light.svg" width="520">
</picture>
```
