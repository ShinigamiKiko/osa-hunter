# Local icons

UI glyphs come from `lucide-static@1.59.0` (ISC); brand logos come from `simple-icons@16.35.0` (CC0). Upstream licenses and the brand disclaimer are kept here.

Only the icons used by the application are included in `js/icons.js`. `js/icon-renderer.js` supplies the SVG markup to browser pages and PDF reports. Icons inherit the surrounding text color; labels carry their meaning.

To refresh, download the pinned packages with `npm pack`, extract them, then run:

```sh
node scripts/vendor-icons.cjs /path/to/lucide-static/package /path/to/simple-icons/package
```

Update the selected names and versions together. No runtime CDN or icon font is needed.
