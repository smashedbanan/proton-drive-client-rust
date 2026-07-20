# proton-drive-client-rust

A pure-Rust CLI client for [Proton Drive](https://proton.me/drive), built from scratch against Proton's public API and the reference [ProtonDriveApps/sdk](https://github.com/ProtonDriveApps/sdk) — no Node/TypeScript/Bun dependency of any kind.

> This is a third-party application, not officially supported by Proton.

## Status

- `login` / `logout` — implemented. SRP authentication (single-password mode only; two-password mode and 2FA are not yet supported), OpenPGP private-key unlock, session persisted in the OS keyring (Keychain / Credential Manager / Secret Service).
- File upload/download — not yet implemented; a separate follow-up plan.

## Build

```bash
cargo build
```

## Usage

```bash
cargo run -- login
cargo run -- logout
```

`login` prompts for your Proton username and password (masked). Requires a real terminal — password entry uses `/dev/tty` directly and will fail when run without a controlling terminal (e.g. through a non-interactive pipe).

## Requirements

- A Proton account using single-password mode with 2FA disabled.

## License

Apache 2.0 — see [LICENSE](./LICENSE).

## Design docs

- [`docs/superpowers/specs/`](./docs/superpowers/specs/) — the design spec for this milestone.
- [`docs/superpowers/plans/`](./docs/superpowers/plans/) — the implementation plan, including the SRP/crypto protocol details.
