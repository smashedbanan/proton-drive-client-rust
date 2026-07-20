# Proton Drive Barebones CLI — Design

## Purpose

A pure-Rust command-line client for Proton Drive with exactly four commands: `login`, `logout`, `upload`, `download`. No TUI, no file listing/browsing, no sync. This is the first vertical slice: prove out real authentication and real encrypted file transfer against Proton's live service, in Rust, with zero JavaScript/TypeScript/Node/Bun runtime dependency.

## Background

Proton publishes an official multi-language SDK at [ProtonDriveApps/sdk](https://github.com/ProtonDriveApps/sdk) — TypeScript (`@protontech/drive-sdk`) and C#, with Kotlin/Swift bindings wrapping the C# SDK. **No Rust implementation exists.** This project reimplements the necessary subset from scratch in Rust, using the TypeScript (`client/js`) and C# (`client/cs`) SDKs and the reference `cli/` (Bun/TypeScript) as the behavioral reference — not as a dependency.

The SDK explicitly excludes authentication, session management, and key handling — that's left to each client. This project must implement Proton's SRP login and OpenPGP key decryption natively.

Proton's operational requirements for any third-party client (from the SDK README) apply regardless of implementation language:
- Must send an honest `x-pm-appversion` header identifying the app (pattern: `external-drive-{name}@{semver}-{channel}+{suffix}`).
- Must talk to official Proton endpoints only.
- Must use event-based sync rather than polling once sync exists (not applicable yet — no listing/sync in this milestone).
- No Proton branding/trademarks; must disclose itself as an unofficial third-party app when prompting for credentials.
- Proton is targeting a breaking cryptographic model migration around end of 2026/early 2027 — anything built against the current crypto model will need a corresponding update then. Not a blocker now, but a known future maintenance cost worth tracking.

## Scope

**In scope:**
- `login` — SRP authentication, 2FA (TOTP) support, single-password mode only (login password decrypts the private key directly; no separate mailbox password).
- `logout` — clear the local session.
- `upload <local-file> <remote-path>` — encrypt and upload a single file to an existing remote folder.
- `download <remote-path> <local-file>` — download and decrypt a single file.

**Explicitly out of scope for this milestone:**
- TUI (planned as a later milestone on top of this).
- File/folder listing, browsing, move/rename/trash, sharing.
- Two-password mode (separate mailbox password).
- Multi-file or recursive/directory transfers.
- Sync, event polling, caching layers.
- Automatic retry/backoff on API errors.
- Cargo workspace split (single binary crate for now).
- Async runtime (sync/blocking HTTP only).

## Architecture

Single binary crate, no workspace:

```
src/
├── main.rs            entry point: parse args, dispatch, map errors → exit codes
├── cli.rs              clap subcommands: Login, Logout, Upload{local,remote}, Download{remote,local}
├── error.rs            one Error enum (thiserror) — network/API/crypto/"not logged in"
├── config.rs           constants: API base URL, x-pm-appversion string
├── session.rs          keyring read/write of the logged-in session
├── srp.rs               Proton's SRP client-side handshake math
├── crypto.rs            OpenPGP key decryption + block encrypt/decrypt/sign
├── api/
│   ├── mod.rs           shared HTTP wrapper (ureq): base URL, headers, bearer token, error mapping
│   ├── auth.rs          login/2FA endpoints
│   └── drive.rs         path resolution, block upload/commit, block download
└── commands/
    ├── login.rs
    ├── logout.rs
    ├── upload.rs
    └── download.rs
```

Chosen over a workspace split (`drive-core` + `drive-cli` mirroring the official SDK/CLI separation) because there is exactly one consumer today; splitting for a hypothetical future TUI consumer is deferred until that TUI milestone actually starts. Chosen over an async (tokio/reqwest) foundation because barebones has no concurrent operations — each command runs once and exits — so sync (`ureq`) keeps the dependency tree smaller. Both are cheap, localized refactors later if/when the TUI milestone needs them.

### Component responsibilities

- **`srp.rs`** — pure math, no I/O. Isolated so it's unit-testable independent of any network call. Proton's SRP variant uses a custom modulus/hashing scheme, not a generic RFC 5054 implementation, so this is hand-ported from the reference SDK rather than sourced from an off-the-shelf `srp` crate.
- **`crypto.rs`** — OpenPGP operations via the `pgp` crate (pure Rust, no C crypto backend to build/link): private key decryption, per-file content key generation, block encrypt/decrypt, signing/verification.
- **`session.rs`** — the only module that touches the OS keyring (via the `keyring` crate — Secret Service/libsecret on Linux, Keychain on macOS, Credential Manager on Windows). `login` writes to it; `logout` clears it; `upload`/`download` read it first and fail fast with a clear "not logged in, run `login`" error if empty.
- **`api/`** — split by surface area, sharing one wrapper for the mandatory `x-pm-appversion` header and bearer-token injection so a new endpoint can't accidentally skip it.
- **`commands/*`** — thin orchestrators calling `session` → `api` → `crypto` in sequence. No business logic of their own, so the real logic stays testable without a CLI harness.

Exact endpoint paths and request/response payload shapes are not fixed by this design — they get extracted from `client/js`/`client/cs` during implementation.

## Data Flow

**Login**
1. Prompt for username + password (masked stdin).
2. Request SRP challenge (salt, server ephemeral, modulus) for that username.
3. `srp.rs` computes the client proof from the password + challenge.
4. Send proof → server returns either a session (UID + access/refresh tokens) or "2FA required."
5. If 2FA required, prompt for the TOTP code and submit it to get the session.
6. Fetch the account's encrypted key material.
7. Derive the key-decryption passphrase from the login password and decrypt the private key (`crypto.rs`).
8. Persist tokens + decrypted key material via `session.rs` into the OS keyring.

**Logout**
1. Load session from keyring.
2. Best-effort call to revoke the session server-side.
3. Clear the keyring entry regardless of whether that call succeeds.

**Upload**
1. Load session; fail clearly with "not logged in" if absent.
2. Resolve the remote parent folder via the Drive API (assumes it already exists — no implicit directory creation).
3. Generate a per-file content key; split the file into blocks; encrypt + sign each block.
4. Request per-block upload targets from the API, PUT the encrypted bytes.
5. Commit the new revision (encrypted name, content key packet, block manifest) to finalize it server-side.
6. Print the resulting remote identifier.

**Download**
1. Load session; fail clearly if absent.
2. Resolve the remote path to its node/revision.
3. Fetch the block manifest, download each encrypted block.
4. Decrypt + verify each block, reassemble in order, write to the local path.
5. Check the final content hash against the manifest so corruption is caught rather than written out silently.

## Error Handling

Single `Error` enum (`thiserror`) with variants: `Network`, `Api` (structured server error — bad credentials, 2FA invalid, rate-limited, etc., carrying Proton's error code + message), `Crypto` (key/block decrypt or signature failure), `NotLoggedIn`, `Io` (local file missing/unwritable). `main.rs` maps any of these to one clean stderr line + exit code 1. No distinct exit codes per failure type unless scripting needs it later. No `panic!`/`unwrap()` on expected failure paths (wrong password, network down, missing file).

Nothing sensitive (password, TOTP code, decrypted key material, tokens) is ever logged or included in an error message.

No automatic retry/backoff — a failed call errors out and the user re-runs the command. Proton's backoff guidance protects against rate-limiting from polling/parallel traffic; a single sequential command has neither, so this is a reasonable simplification, not a compliance gap. Add it if real usage ever hits a 429.

## Testing

- `srp.rs`: pure unit tests, no network — checked against whatever reference test vectors the SDK/`go-srp` expose, since a subtle bug here is dangerous and easy to miss.
- `crypto.rs`: round-trip unit tests (encrypt→decrypt, sign→verify) using locally-generated keys — doesn't require a real Proton account to verify the plumbing.
- `commands/*`: tested against a faked `api` layer, verifying orchestration order and error propagation (e.g., a simulated "2FA required" response triggers the TOTP prompt).
- Real login/upload/download against an actual Proton account is inherently manual/integration-level, since there's no way to run Proton's API locally. This stays a manual verification step, not part of automated tests.

Plain `#[test]` functions throughout; no test framework or fixture layer for a project this size.

## Open Risks

- **SRP correctness**: Proton's SRP variant must be ported precisely; a subtle math error can fail silently or insecurely. Needs careful cross-checking against the reference implementation.
- **Protocol specifics**: exact Drive API endpoints, payload shapes, and the block-encryption/manifest format are not yet extracted from the reference SDK — that happens during implementation, not in this design.
- **Upcoming crypto migration** (targeted end of 2026/early 2027): will require a follow-up update once Proton ships it; not addressed by this milestone.
