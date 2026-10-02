# AGENTS.md

marksocks: a small SOCKS5 proxy (CONNECT + UDP ASSOCIATE, optional user/pass auth) on top of
fast-socks5 and Tokio. It can set a Linux `SO_MARK` on destination-facing sockets. It is
shipped for OpenWrt as a signed apk feed on GitHub Releases. README.md is the user doc.

## Layout
- `src/main.rs`: CLI (`--config`, `--check`), listener, shutdown. `src/lib.rs`: `Config`,
  module wiring. `src/socks.rs`, `src/outbound.rs` (marked sockets), `src/udp.rs`.
- `tests/` (tcp, udp, `mark_linux.rs`), `bench/relay.rs`.
- `config.example.toml`: every key at its default. CI requires it to equal
  `openwrt/marksocks/files/config.toml`.
- `openwrt/marksocks/`: OpenWrt package. The repo itself is an OpenWrt feed.

## Key decisions
- Config comes only from a TOML file (`deny_unknown_fields`). No runtime CLI flags, no env.
- Marking is off by default: `mark` absent means no `SO_MARK`. When `mark` is set and setting
  it fails, the request is rejected; traffic is never sent unmarked. Only outbound sockets
  are marked.
- `request_timeout`, `skip_auth`, `dns_resolve`, `allow_udp`, `allow_no_auth` and `nodelay`
  are inherited from fast-socks5's server config. `allow_udp` and `nodelay` default to true
  (the library defaults to false). See `config.example.toml`.
- `log_level` defaults to `off`. The `fast_socks5` log target is capped at info, because it
  logs credentials at debug. Never log credentials or payloads.

## Commands
```sh
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
# SO_MARK proofs (need CAP_NET_ADMIN): sudo, or Docker
sudo -E env "PATH=$PATH" cargo test --locked --test mark_linux -- --ignored
docker run --rm --cap-add NET_ADMIN -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/tmp/t rust:1.96 \
  sh -c 'rustup update stable && cargo test --locked --test mark_linux -- --ignored'
# Failure path: --cap-drop NET_RAW --cap-drop NET_ADMIN, then run without --ignored
cargo bench --locked --bench relay        # BENCH_TCP_MIB / BENCH_CONNECTS / BENCH_UDP_ROUNDS
MARKSOCKS_BENCH_PROXY=192.168.1.1:1080 MARKSOCKS_BENCH_TARGET_IP=192.168.1.10 cargo bench --locked --bench relay  # external proxy
```

## OpenWrt packaging and releases
- Feed users build from the checkout via `rust-package.mk` (the SDK's rust/host and rustc).
- With `MARKSOCKS_PREBUILT=/abs/path/marksocks` set during `scripts/feeds` and `make`, the
  package recipe skips rust entirely and packages that binary byte for byte. The release
  `openwrt` job uses this with the musl binary from the `binaries` job.
  - Matrix entries hold only `version`/`target`/`subtarget`/`arch`. `arch` maps to the
    Rust target in a `case`, and an unknown arch fails.
- CI and release always build with the latest stable Rust (`rustup update stable` in every
  job, no toolchain cache). Nothing is compiled from source as a tool: zig comes from
  setup-zig, cargo-zigbuild from install-action with `fallback: none`.
- Signing (tag pushes only) uses the secrets `APK_SIGNING_KEY` (private PEM) and
  `APK_PUBLIC_KEY`.
  - The pair must match. `APK_PUBLIC_KEY` is published unchanged as `marksocks.pem`, and its
    file SHA-256 goes in the release notes.
  - To rotate: new P-256 pair (`openssl ecparam -name prime256v1 -genkey -noout`), replace
    both secrets, tag. Routers must then install the new `marksocks.pem`.
  - Never commit any key file. Throwaway test keys go under `target/`.

## Preferences
- Do not commit, push or stage unless asked.
- CI is unpinned and latest on purpose: ubuntu-latest, major action tags, stable Rust, latest
  zig and cargo-zigbuild.
- Keep code small and boring (stdlib first, no speculative abstractions; `// ponytail:` notes).
