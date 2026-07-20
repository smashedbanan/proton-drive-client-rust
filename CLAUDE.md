# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build: `cargo build`
- Test all: `cargo test`
- Test one module: `cargo test srp::` (or `crypto::`, `session::`, `api::`, `cli::`)
- Test one case: `cargo test srp::exchange_tests::srp_exchange_is_internally_consistent_against_real_modulus`
- Run: `cargo run -- login` / `cargo run -- logout` — requires a real terminal; password entry opens `/dev/tty` directly and fails without a controlling terminal (e.g. a non-interactive pipe).

## Architecture

Single binary crate (`proton-drive`), no Cargo workspace, no async runtime — `ureq` for blocking HTTP. This is a deliberate choice, not an oversight: see "Global Constraints" in `docs/superpowers/plans/2026-07-19-proton-drive-cli-auth.md` before introducing a workspace split or an async runtime.

Module layout, bottom-up by dependency:
- `srp.rs` — pure math, no I/O. Proton's SRP-6a *variant*: server-signed modulus verification, a custom `expand_hash` primitive in place of every textbook `H()`, little-endian encoding throughout (including the modulus itself — this was a real bug caught during planning; big-endian parses as non-prime). Also the two distinct bcrypt-based password derivations — the SRP secret and the private-key passphrase use different salt handling and must not be conflated. The exact deviations from textbook SRP-6a are documented in the plan doc, not re-derived here.
- `crypto.rs` — OpenPGP private-key unlock via the `pgp` crate, used to validate a derived password actually works. `pgp` 0.20.0 depends on `rand 0.8` internally, which is trait-incompatible with the `rand 0.10` used elsewhere in this crate — the `rand08` dev-dependency (`rand@0.8`, renamed via `package = "rand"`) exists solely so this module's *tests* can generate a throwaway key; production code needs no RNG.
- `api/` — `mod.rs` wraps `ureq`. Proton signals success/failure via a top-level JSON `Code` field independent of HTTP status, so `http_status_as_error(false)` is set and the code checks `Code` itself rather than relying on ureq's status-based errors. `auth.rs` holds the auth/keys/users request and response types.
- `session.rs` — the only module that touches the OS keyring. Holds `Credentials`: session tokens plus the *derived* key passphrase (from `srp::compute_key_password`) — never the login password itself.
- `commands/` — thin orchestrators (`login.rs`, `logout.rs`) wiring `srp` → `api` → `crypto` → `session` together. No business logic of their own; `ApiClient` is currently a concrete type with no mock seam, so this layer has no automated test coverage (a known gap, deferred to the next plan).

`login` is hardcoded to auth version 4 and single-password mode — it errors clearly (not silently) if the server reports a different version or `PasswordMode != 1`. 2FA is explicitly out of scope for this milestone: Proton's own open-source reference SDK has no working call site for it to port from.

File upload/download (Drive path resolution, block encryption, the Drive-specific API) do not exist yet — that's a separate, not-yet-written plan.

For the exact protocol details (why each SRP deviation exists, which values are little-endian, the bcrypt salt construction, the block-upload protocol reference material) read `docs/superpowers/plans/2026-07-19-proton-drive-cli-auth.md` rather than re-deriving them — it was written and validated against Proton's real reference SDK and a live account.
