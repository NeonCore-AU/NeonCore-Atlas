# Development

## Rust

```sh
cargo fmt --all
cargo test --workspace
cargo run -p atlas-cli -- status
cargo run -p atlas-cli -- rules
cargo run -p atlas-cli -- dns
cargo run -p atlas-cli -- latency
cargo run -p atlas-daemon -- run
```

## i18n

```sh
python3 i18n/scripts/generate-pseudo-locale.py
./i18n/scripts/check-hardcoded-strings.sh
./i18n/scripts/check-missing-translations.sh
```

## Platform Apps

- iOS/macOS: open the Swift sources in Xcode or create app targets around the provided source layout.
- Android: open `apps/android` in Android Studio.
- Windows: open `apps/windows` with Visual Studio and Windows App SDK installed.
- Linux: install GTK4/libadwaita development packages, then build the Rust app skeleton.
