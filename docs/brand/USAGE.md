# exa-tools brand assets

| File | Use |
|---|---|
| `exa-tools-banner-{dark,light}.svg` | README hero, once per page. Transparent ground. |
| `exa-tools-wordmark-{dark,light}.svg` | Docs headers, inline. No Exabeam element. |
| `exa-tools-mark-{dark,light}.svg` | Square app mark: favicon, avatar, MCP listing. |
| `favicon.ico`, `favicon-*.png` | 16/32/64 ico; 180 apple-touch; 512 PWA. |
| `social-preview.{svg,png}` | GitHub Settings -> Social preview (1280x640). |

## Construction (measured from the official 2025 kit)

* gap unit = width of the "m" in Exabeam = **0.7163 x logo height**, used both sides of the rule
* divider = **1px**, white @ 50% (dark) / black @ 40% (light), height = logo height
* partner x-height matched to Exabeam x-height = **0.5777 x logo height**
* wordmark set in **JetBrains Mono Bold**, converted to outlines - no font dependency

## Rules

* Clear space = **1 x logo height** on all four sides. The SVG bakes in 0.25x only;
  the remainder must come from page layout.
* Minimum banner height **17px**; below that use the wordmark alone.
* Never recolour, rotate, distort or add effects to the Exabeam bug.
* Dark backgrounds use `Logo-Color-Light`; light backgrounds use `Logo-Color-Dark`.
  The kit's names refer to the logo's colour, not the background.

## Attribution

The Exabeam bug is a trademark of Exabeam, Inc., used here under the 2025 Brand Style
Guide's Partnerships construction. exa-tools is not an official Exabeam product.
