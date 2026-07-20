# proton-drive-client-rust

A pure-Rust CLI client for [Proton Drive](https://proton.me/drive), built from scratch against Proton's public API and the reference [ProtonDriveApps/sdk](https://github.com/ProtonDriveApps/sdk) — no Node/TypeScript/Bun dependency of any kind.

> This is a third-party application, not officially supported by Proton.

## Status

- `login` / `logout` — implemented. SRP authentication (single-password mode only; two-password mode and 2FA are not yet supported), OpenPGP private-key unlock, session persisted in the OS keyring (Keychain / Credential Manager / Secret Service).
- `upload` — implemented. Client-side encrypts a local file (OpenPGP node keys, per-file AES-256 content keys, 4 MiB blocks with optional AEAD framing) and uploads it into an existing Drive folder. A same-name conflict always creates a new revision rather than erroring or prompting.
- `download` — not yet implemented; the natural next milestone.

## Build

```bash
cargo build
```

## Usage

```bash
cargo run -- login
cargo run -- logout
cargo run -- upload <local-file> <remote-folder>
```

`login` prompts for your Proton username and password (masked). Requires a real terminal — password entry uses `/dev/tty` directly and will fail when run without a controlling terminal (e.g. through a non-interactive pipe).

`upload` encrypts `<local-file>` and uploads it into `<remote-folder>` — an existing folder path rooted at `/my-files/...` — keeping the local file's own name. The destination folder must already exist; `upload` does not create folders along the way.

## Requirements

- A Proton account using single-password mode with 2FA disabled.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
