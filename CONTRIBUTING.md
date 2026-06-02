# Contributing

Thanks for helping build NeonCore Atlas. Keep changes small, documented, and friendly to native platform conventions.

## Development Rules

- Keep shared logic in Rust crates when it is not platform-specific.
- Keep platform VPN and service integration behind adapters.
- Do not add telemetry or credentials.
- Do not hard-code production user-visible strings. Add localization keys and resources instead.
- Protocol and packet-path changes need design notes, tests, and security review.

## Checks

```sh
cargo fmt --all
cargo test --workspace
./i18n/scripts/check-hardcoded-strings.sh
./i18n/scripts/check-missing-translations.sh
```
