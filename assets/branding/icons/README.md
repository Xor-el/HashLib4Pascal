# Package icons

| File | Contents |
|------|-----------|
| [`HashLib4Pascal.ico`](HashLib4Pascal.ico) | Multi-size Windows icon (16, 32, 48, 256), generated from [this logo](../logo.svg). |

## Using in Delphi (`.dproj`)

1. Open the project in the IDE.
2. **Project → Options → Application** (or **Icons** depending on version).
3. Set **Application icon** to [`HashLib4Pascal.ico`](HashLib4Pascal.ico) (path relative to the `.dproj`; from the repo root that is `assets/branding/icons/HashLib4Pascal.ico`).

Alternatively, your `.dproj` may contain an `<Icon_MainIcon>` or similar property pointing at an `.ico` file; set it to a path **relative to the project file** (you may copy the icon next to the `.dproj` if the IDE resolves paths more reliably that way).

## Using in Lazarus (`.lpi`)

1. **Project → Project Options → Application** — set **Icon** to this `.ico`.
2. Or edit the `.lpi` XML: look for `IconPath` / `Icon` style keys and set the path (relative to `.lpi` is common).

## Regeneration

When [this logo](../logo.svg) changes, rebuild the ICO with **Inkscape** or **ImageMagick** following the workflow [described here](../README.md), then combine sizes into a multi-resolution `.ico` if your tool does not do that in one step.
