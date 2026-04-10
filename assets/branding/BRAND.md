# HashLib4Pascal — lightweight brand guide

## Primary mark

- **Default:** [`logo.svg`](logo.svg) — **shred-to-block**: lavender **input shards** on the left, a short **gold arrow**, and a **solid digest block** on the right with two subtle horizontal lines (abstract output bytes). Reads as “any input → one fingerprint.”
- **Dark UI:** [`logo-dark.svg`](logo-dark.svg) — same layout with **brighter** lavender shards, **amber** arrow and block, on a **deeper violet-black** badge.

## Palette (default logo)

| Role | Hex | Notes |
|------|-----|--------|
| Badge top | `#4a3d66` | Gradient start. |
| Badge bottom | `#261d38` | Gradient end. |
| Input shards | `#c4b5fd` at 55% opacity | Arbitrary / unstructured input. |
| Arrow | `#e8c547` | Direction into digest. |
| Digest block | `#f7e08a` | Fixed-size result. |
| Block detail | `#261d38` at 35% opacity | Suggested digest lines (not text). |

Dark variant uses `#1a1428`–`#0a0810`, shards `#a78bfa` at 70%, arrow `#fde68a`, block `#ffe082`, detail `#0a0810` at 45%.

**Banner background** (flat fill behind the logo for wide social and Open Graph PNGs [here](export/)): RGB **53, 45, 76** (`#352b4c`), aligned with the badge mid-tone.

## Typography (pairing)

The logo has **no embedded wordmark**. When setting type next to the mark:

- Prefer **clean sans-serif** UI fonts (e.g. Segoe UI, Inter, Source Sans 3).
- **Do not** use Embarcadero product logotypes alongside this mark in a way that suggests an official bundle.

## Clear space

Keep padding around the badge at least **1/4 of the mark width** on a square canvas. Do not crop the rounded corners flush to the edge of arbitrary crops.

## Minimum size

- **Favicon / IDE:** target **16×16** in ICO; **32×32** or larger is clearer.
- **README / docs:** **128–200 px** wide for the SVG is typical.

## Correct use

- Scale **uniformly**.
- Use `logo-dark.svg` on **dark** pages for contrast.
- Prefer **SVG** on the web; **PNG** where required (some social crawlers).

## Incorrect use

- Do not **stretch**, **skew**, or **rotate** the mark for effect.
- Do not **recolor** outside the documented palette without updating this doc (palette table above).
- Do not **crop** to only the digest block or only the shards without the badge frame (loses identity).
- Do not place **third-party logos inside** the badge.

## Wordmark

“HashLib4Pascal” in plain text beside or below the mark is enough; no custom logotype is required.
