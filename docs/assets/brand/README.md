# Termivar web brand assets

The source image in this directory was supplied by the project owner as the
canonical Termivar visual identity. The website uses fixed, byte-pinned raster
derivatives rather than tracing or redrawing the mark.

## Source

| File | Dimensions | SHA-256 |
| --- | ---: | --- |
| `termivar-logo-source.jpg` | 1182 × 394 | `6BD8ABD87A38239D68728C402273555FF90A6F335F8068AE720E68E70AF0EF6A` |

The source is a 24-bit JPEG with an opaque white background. It is not treated
as a transparent or vector master.

## Site derivatives

| File | Dimensions | Purpose | SHA-256 |
| --- | ---: | --- | --- |
| `termivar-lockup.png` | 1128 × 296 | Homepage wordmark | `E21E8D5C00FEA8A57E22EBC667D56BFA4C80A026F0ACB3C43890EE8A84B995B4` |
| `termivar-mark.png` | 320 × 320 | Documentation navigation and touch icon | `89FF365DA9ADDE9AF73EFB834692DFDE352A1B3472A164C0411B36A76F365DD9` |
| `termivar-favicon.png` | 64 × 64 | Browser favicon | `6A691F681A12B7F723BF32841629CEAD734CCDCDC7D3BEB0284CA99A45DC436C` |
| `termivar-social-card.png` | 1200 × 630 | Open Graph and Twitter card | `1C013027CC2BE768374E41DB65F5A4FE81BECFFD4E011CCDA89475108CDD9489` |

The lockup uses source crop `[32, 40, 1160, 336)`. The mark uses source crop
`[30, 28, 350, 348)`. The committed favicon is a 64 × 64 reduction of that
fixed mark crop. The social card places the unchanged lockup on a static,
light grid with the approved positioning line. Derivatives contain no EXIF or
machine-specific timestamps. The hashes above, rather than an undocumented
claim of reproducible generation, are the review boundary for the committed
web assets.

Do not auto-trace this JPEG into SVG, infer transparency from its compressed
white background, invert it for dark mode, or alter its green gradient. A
future transparent/dark-mode or simplified small icon should start from an
owner-approved vector or lossless RGBA master.
