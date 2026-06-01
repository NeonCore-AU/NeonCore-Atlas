# Internationalization

NeonCore Atlas is multilingual from the first version. English (Australia) (`en-AU`) is the source language. Initial locales are `en-AU`, `zh-Hans`, and pseudolocale `en-XA`.

## Platform Formats

- iOS and macOS: Apple String Catalogs (`.xcstrings`).
- Android: native `strings.xml` and `plurals.xml` resources.
- Windows: WinUI `.resw` resources under `Strings/<locale>/Resources.resw`.
- Linux: Fluent (`.ftl`) files.
- Rust CLI and daemon: Fluent (`.ftl`) files embedded by the binary.

## Adding a String

1. Add a semantic key to `i18n/keys.yml`.
2. Add source text and translator context where the platform format supports it.
3. Add translations or temporary source-language fallbacks for every supported locale.
4. Use placeholders instead of concatenating partial sentences.
5. Run the i18n checks.

## Adding a Language

1. Add the locale to `i18n/locales.yml`.
2. Add resources for every platform.
3. Update pseudolocale and missing-translation checks.
4. Verify UI layouts with expanded text.

## Pseudolocalization

`en-XA` intentionally expands and accents strings to reveal clipping, truncation, and hard-coded text. Run `i18n/scripts/generate-pseudo-locale.py` after changing source strings.

## Hard-Coded Strings

Production UI, CLI, daemon output, menu items, tooltips, accessibility labels, empty states, notifications, and errors must use localization resources. Debug logs and tests may use raw strings.
