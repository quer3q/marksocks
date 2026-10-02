# marksocks

A small SOCKS5 proxy that can put a Linux `SO_MARK` on its outgoing traffic, so a firewall
rule, policy route or transparent proxy can recognise what went through it. It is built on
[fast-socks5](https://github.com/dizda/fast-socks5) and Tokio, supports `CONNECT` and
`UDP ASSOCIATE` (IPv4, IPv6, domain names) with optional username/password auth, and is
configured by one TOML file. OpenWrt builds for routers are available too, as a signed apk
feed on GitHub Releases ([install](#install-on-openwrt)).

## The mark contract

- **Marking is off by default.** If `mark` is absent from the config, no socket gets a mark.
- When `mark` is set (decimal or hex, non-zero, e.g. `mark = 0x10000000`), **only
  destination-facing sockets** are marked: outbound TCP connections and outbound UDP
  sockets. The mark is set before `connect()` or the first `send`. Every connection attempt
  to every resolved address is marked.
- The listening socket, accepted client connections, the client-facing UDP relay socket
  and the queries to the `dns` server are **never** marked. DNS goes to a local resolver,
  not to a destination.
- If the mark cannot be set, the request is **rejected**: a TCP `CONNECT` gets a SOCKS
  "general failure" reply, and a UDP datagram is dropped with a warning. Traffic is never
  sent unmarked. Setting a mark needs `CAP_NET_ADMIN`, or `CAP_NET_RAW` on Linux >= 5.17.
  On OpenWrt the service runs as root, which has both. On non-Linux builds marking always
  fails.

## Build

`rust-toolchain.toml` selects the **stable** channel (plus rustfmt, clippy and the two musl
targets). `Cargo.lock` is committed; always build with `--locked`.

```sh
rustup update stable                    # the toolchain file does not update an old stable
cargo build --release --locked          # target/release/marksocks
```

Static musl binaries are built the way CI does it, with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and
[zig](https://ziglang.org/download/) (both prebuilt releases; zig must be on `PATH`):

```sh
cargo zigbuild --locked --release --target aarch64-unknown-linux-musl
cargo zigbuild --locked --release --target x86_64-unknown-linux-musl
```

CI and the release workflow always compile with the **latest stable Rust**: every job runs
`rustup update stable` first and nothing caches a toolchain. They never compile a toolchain
or a tool from source: Rust comes from rustup, zig from `mlugg/setup-zig` and cargo-zigbuild
from its release binaries (`taiki-e/install-action`, no source fallback). The release
notes name the rustc that built the release.

The OpenWrt `.apk` in a release contains exactly that musl binary. The release workflow's
`openwrt` job downloads the prebuilt OpenWrt SDK for each matrix entry (`version`, `target`,
`subtarget`, `arch`), maps `arch` to the Rust target (`aarch64_*` to
`aarch64-unknown-linux-musl`, `x86_64` to `x86_64-unknown-linux-musl`), and only packages
the binary (`MARKSOCKS_PREBUILT`, see [`openwrt/marksocks/Makefile`](openwrt/marksocks/Makefile)).
It does not build the SDK's `rust/host` and needs no other feed. On a tag push it also
signs the apk index. If you build the package yourself from the feed (below), your SDK or
buildroot compiles it with its own rustc, whose version is not up to us.

## Install on OpenWrt

### Install from the signed apk repository (OpenWrt 25.12)

Every GitHub release is also a small apk repository: a signed index `packages.adb` that
lists only marksocks, the package it points to, and the public key `marksocks.pem` that
verifies the index. The repository URL always points at the latest release:

```
https://github.com/quer3q/marksocks/releases/latest/download/packages.adb
```

Today the packages are built with the OpenWrt **25.12.5** SDK for the `aarch64_generic`
package architecture (e.g. NanoPi R3S). Check that the router matches:
`cat /etc/apk/arch`.

```sh
# 1. Trust the key that signs the index.
wget -O /etc/apk/keys/marksocks.pem \
    https://github.com/quer3q/marksocks/releases/latest/download/marksocks.pem
sha256sum /etc/apk/keys/marksocks.pem

# 2. Add the repository.
echo 'https://github.com/quer3q/marksocks/releases/latest/download/packages.adb' \
    >> /etc/apk/repositories.d/customfeeds.list

# 3. Install. No --allow-untrusted.
apk update && apk add marksocks
```

Check the fingerprint printed in step 1 before step 3. It is the SHA-256 of the bytes
of the `marksocks.pem` file.

- The notes of the [latest release](https://github.com/quer3q/marksocks/releases/latest)
  give the expected value: "SHA-256 of the file's bytes: `<hash>`; on the router,
  `sha256sum /etc/apk/keys/marksocks.pem` must print it".
- The release workflow log prints it as
  `marksocks.pem SHA-256 (of the file's bytes): <hash>`.

If the values differ, delete `/etc/apk/keys/marksocks.pem` and stop.

How the trust works:

- apk verifies the signature of `packages.adb` with the keys in `/etc/apk/keys`. The index
  records the hash of each package, and apk rejects a package file that does not match it.
- Without the key, or with a different key, `apk update` reports
  `packages.adb: UNTRUSTED signature` and `apk add marksocks` finds no such package.

Updates:

- `apk update && apk upgrade marksocks` installs a newer release once it is the latest one.
- apk fetches the package as `.../releases/latest/download/marksocks-<version>-r<n>.apk`,
  relative to the repository URL. If a new release was published after your last
  `apk update`, that name no longer exists in the latest release and the download fails.
  Run `apk update` again.
- To pin one release instead of following the latest, use
  `https://github.com/quer3q/marksocks/releases/download/v<version>/packages.adb` as the
  repository line.

The package installs:

| Path | What |
|---|---|
| `/usr/bin/marksocks` | the binary |
| `/etc/marksocks/config.toml` | runtime config (conffile, mode 0600) |
| `/etc/config/marksocks` | UCI service section (conffile) |
| `/etc/init.d/marksocks` | procd init script |

The service is installed **disabled**. Edit `/etc/marksocks/config.toml`, then:

```sh
marksocks --check --config /etc/marksocks/config.toml
uci set marksocks.main.enabled=1 && uci commit marksocks
service marksocks restart
service marksocks status; logread -e marksocks
```

### Build it into a firmware image (ImageBuilder)

The 25.12 ImageBuilder resolves packages from the repositories listed in its
`repositories` file and checks their index signatures against `keys/`. Add the marksocks
repository and key there, and put `marksocks` in `PACKAGES`:

```sh
# in openwrt-imagebuilder-25.12.5-rockchip-armv8.Linux-x86_64
BASE=https://github.com/quer3q/marksocks/releases/latest/download
wget -O keys/marksocks.pem "$BASE/marksocks.pem"
echo "$BASE/packages.adb" >> repositories
make image PROFILE=friendlyarm_nanopi-r3s PACKAGES="marksocks"
```

For an [openwrt-builder](https://github.com/quer3q/openwrt-builder) style workflow, add a
step next to its "Add Passwall2 apk feed" step. The step puts the key in the ImageBuilder's
`keys/` (for the build) and in `files/etc/apk/keys/` (so the router trusts later updates).
It appends the repository line to `repositories` and to the image's
`files/etc/apk/repositories.d/customfeeds.list`:

```yaml
      - name: Add marksocks apk feed
        run: |
          BASE="https://github.com/quer3q/marksocks/releases/latest/download"

          # Signing key: for the Image Builder, and for the router itself
          wget -q -O imagebuilder/keys/marksocks.pem "${BASE}/marksocks.pem"
          mkdir -p imagebuilder/files/etc/apk/keys imagebuilder/files/etc/apk/repositories.d
          cp imagebuilder/keys/marksocks.pem imagebuilder/files/etc/apk/keys/marksocks.pem

          # Feed: resolve marksocks at build time, and allow `apk upgrade` on the router
          echo "${BASE}/packages.adb" \
            | tee -a imagebuilder/repositories \
                     imagebuilder/files/etc/apk/repositories.d/customfeeds.list > /dev/null
```

Then add `marksocks` to the `PACKAGES` list of its "Build image" step, and keep
`FILES="files"`. If the workflow later copies its own `etc/apk/repositories.d/customfeeds.list`
into `imagebuilder/files/`, that copy replaces the lines appended above. For a reproducible
image, use `https://github.com/quer3q/marksocks/releases/download/v<version>` as `BASE`
instead of `latest`.

A single release file also works: copy `marksocks-<version>-r<n>.apk` (keep that name, the
ImageBuilder looks packages up as `<name>-<version>.apk`) into the ImageBuilder's
`packages/` directory, which it indexes and signs with a local key.

The init script is enabled in the image, but UCI `enabled` is still `0`. To ship a working
configuration, pass your own files with `FILES=<dir>`, e.g. `<dir>/etc/marksocks/config.toml`
(mode 0600) and `<dir>/etc/config/marksocks` with `option enabled '1'`.

### Use this repo as an OpenWrt feed

The repository is an OpenWrt feed: [`openwrt/marksocks/Makefile`](openwrt/marksocks/Makefile)
has no `PKG_SOURCE` and builds the crate of the checkout it sits in, so you get exactly the
commit the feed points at. It works in the SDK of the OpenWrt release you target or in a
full buildroot. The `packages` feed (it provides `lang/rust`) must be in the same
`feeds.conf`; the SDK's `feeds.conf.default` already has it.

```sh
cd openwrt-sdk-25.12.5-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64   # or a buildroot
cp feeds.conf.default feeds.conf      # SDK; a buildroot may already have feeds.conf
echo 'src-git marksocks https://github.com/quer3q/marksocks.git;main' >> feeds.conf
./scripts/feeds update -a
./scripts/feeds install marksocks     # also installs rust (rust/host) from packages
make menuconfig                       # Network > Web Servers/Proxies > marksocks = M
make package/marksocks/compile V=s
find bin/packages -name 'marksocks-*.apk'   # marksocks-<version>-r1.apk
```

To pin a release instead of following `main`, pin the commit its tag points to.
`scripts/feeds` never pulls a `^<sha>` feed again, and a commit cannot move the way a tag
can. This replaces the `marksocks` line added above (a feed name may appear only once):

```sh
v=0.0.3
sha=$(git ls-remote https://github.com/quer3q/marksocks.git "refs/tags/v$v" "refs/tags/v$v^{}" | tail -n1 | cut -f1)
sed -i "s|^src-git marksocks .*|src-git marksocks https://github.com/quer3q/marksocks.git^$sha|" feeds.conf
./scripts/feeds update marksocks && ./scripts/feeds install marksocks
```

`./scripts/feeds update marksocks` fetches new commits of a `;main` feed; a changed
`Cargo.toml`, `Cargo.lock` or `src/` is copied and rebuilt on the next compile. For a local
checkout use `src-link marksocks /path/to/marksocks`; keep the SDK outside that checkout,
because the feed is scanned recursively.
Instead of `make menuconfig` you can run
`echo CONFIG_PACKAGE_marksocks=m >> .config && make defconfig`.

**Build cost:** before marksocks itself, the SDK builds `rust/host` (rustc with LLVM) from
source. That takes hours and many GB of disk, and the compiler is the one in the release's
packages feed (1.94.0 for 25.12.5), not the latest stable. To package a binary you built
yourself instead (as the release workflow does), export
`MARKSOCKS_PREBUILT=/abs/path/to/static/marksocks` before `./scripts/feeds update` and
`make`; then neither rust nor the packages feed is needed.

## Configuration

### TOML file (`/etc/marksocks/config.toml`)

All runtime settings live in one TOML file. The default path is
`/etc/marksocks/config.toml`; pass another one with `marksocks --config <path>`.
`marksocks --config <path> --check` validates the file, prints `config ok` and exits 0. On
an error it exits non-zero with the line and reason. Unknown keys are errors, so typos are
caught. Durations are whole seconds.

Every key is optional. An empty file means: loopback listener, no auth, **no marking**,
logging off, the timeouts and connection limit shown below, and fast-socks5's own
defaults for the inherited keys (marked *), except `allow_udp` and `nodelay`. [`config.example.toml`](config.example.toml) lists every key at its
default, with comments.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `"127.0.0.1:1080"` | Address and port for SOCKS5 clients. |
| `log_level` | `"off"` | `off`, `error`, `warn`, `info`, `debug` or `trace`. Startup and config errors always go to stderr. Credentials and payloads are never logged. |
| `mark` | absent (off) | `SO_MARK` for destination-facing sockets, decimal or `0x` hex, non-zero. See [the mark contract](#the-mark-contract). |
| `handshake_timeout` | `10` | Seconds a client has for negotiation, auth and its request. `0` = no limit. |
| `idle_timeout` | `300` | Seconds without traffic in either direction before a TCP relay or UDP association is closed. `0` = no limit. |
| `max_connections` | `512` | Concurrent client connections. Extra clients are closed at once. `0` = no limit. |
| `dns` | absent (system resolver) | DNS server for domain destinations, `"ip:port"`, e.g. `"127.0.0.1:5353"`. Asked for A records only (CNAME chains are followed), over UDP with a TCP retry for truncated answers, within `request_timeout`. Answers are cached, see `dns_cache_size`. NXDOMAIN or no A record fails like an unknown host. Unused when `dns_resolve = false`. Use it when the system resolver returns addresses that must not be used here, e.g. passwall2 FakeDNS (`198.18.x`). |
| `dns_cache_size` | `1024` | Resolved domain names cached: answers from `dns` for their record TTL (at most 10 minutes), system resolver answers for 60 seconds. When full, expired entries and then those expiring soonest are dropped. NXDOMAIN, empty answers and errors are not cached. `0` = no cache. |
| `request_timeout` * | `10` | Seconds for DNS resolution plus all connection attempts to one destination. Must be >= 1. |
| `skip_auth` * | `false` | Skip SOCKS5 method negotiation (not RFC compliant). Cannot be combined with `[auth]`. |
| `dns_resolve` * | `true` | Resolve domain destinations on the router. `false` rejects them with "address type not supported" (TCP) or drops them (UDP). |
| `allow_udp` * | `true` | Accept `UDP ASSOCIATE`. `false` replies "command not supported". **fast-socks5's default is `false`.** |
| `allow_no_auth` * | `false` | With `[auth]` set, also accept clients that only offer "no authentication". |
| `nodelay` * | `true` | `TCP_NODELAY` on client and outbound TCP sockets. **fast-socks5's default is `false`.** |
| `[auth]` `username`, `password` | absent (no auth) | Both required when the table is present, 1 to 255 bytes each. |

\* Inherited from fast-socks5's server `Config`, with the same names and meaning.
`execute_command` is not exposed, because a standalone proxy always executes commands.

The binary does not check file permissions. **If you set `[auth]`, keep the file at mode
0600** (`chmod 600 /etc/marksocks/config.toml`). The package installs it with that mode.
Credentials are never put on the command line.

### UCI (`/etc/config/marksocks`)

UCI only controls the service. Everything else is in the TOML file.

```
config marksocks 'main'
	option enabled '0'                                # 1 = start the service
	option config_file '/etc/marksocks/config.toml'   # must exist
```

The init script validates these options. Before it starts, it runs
`marksocks --check --config <config_file>`. If that fails, it logs the reason (see
`logread -e marksocks`) and does not start the instance. On a reload, an instance that is
already running is stopped in that case, so check the file before you reload. procd
supervises the process: it respawns it, sets `nofile` to 4096, allows 10 seconds for a
graceful stop, and sends stderr to logd (at `daemon.err` priority, whatever the log
level). `service marksocks reload` restarts the instance only when the TOML file has
changed. While the service is registered with procd, a UCI change applied with
`uci commit marksocks && reload_config` (or LuCI) reloads it too. A restart drops open
connections. For connection logs, set `log_level = "info"`.

### UDP reply addresses

Each reply datagram's SOCKS header carries the address the client sent to, not only where
the reply came from. If the client sent to a domain (`ATYP=3`), the reply carries the same
name and port. Clients such as xray map replies back by that name, e.g. to a FakeDNS
address. If the client sent to an IP, the reply carries the source IP. If several names
the client used in one association resolve to the same address and port, replies carry
the name used most recently.

## Enabling LAN access

By default marksocks listens on `127.0.0.1:1080`, so only the router itself can use it.
To serve LAN clients:

1. Set `listen` to the router's LAN address, e.g. `listen = "192.168.1.1:1080"`. Or use
   `"0.0.0.0:1080"` for all interfaces, which includes WAN, so the firewall must block it
   there.
2. **Always add an `[auth]` table** and `chmod 600` the TOML file. Without auth, anyone who
   can reach the port can use your connection.
3. Check the firewall. OpenWrt's fw4 accepts all input from the `lan` zone and rejects
   input from `wan` by default, so every LAN host can reach the port. To allow only some
   hosts, add an ACCEPT rule for them **followed by** a REJECT rule for everyone else. fw4
   emits rules in UCI order, ahead of the zone's default accept:

   ```sh
   uci add firewall rule
   uci set firewall.@rule[-1].name='marksocks-allow'
   uci set firewall.@rule[-1].src='lan'
   uci set firewall.@rule[-1].src_ip='192.168.1.10'    # repeat src_ip via `uci add_list` for more hosts
   uci set firewall.@rule[-1].proto='tcp'
   uci set firewall.@rule[-1].dest_port='1080'
   uci set firewall.@rule[-1].target='ACCEPT'
   uci add firewall rule
   uci set firewall.@rule[-1].name='marksocks-reject'
   uci set firewall.@rule[-1].src='lan'
   uci set firewall.@rule[-1].proto='tcp'
   uci set firewall.@rule[-1].dest_port='1080'
   uci set firewall.@rule[-1].target='REJECT'
   uci commit firewall && service firewall reload
   fw4 print | sed -n '/chain input_lan {/,/}/p'   # allow first, then reject, then accept_from_lan
   ```

   Only the TCP port needs a rule. UDP ASSOCIATE relays use a random UDP port, and
   marksocks only accepts datagrams from the IP of an accepted TCP client.
4. Restart: `service marksocks restart`.

## Benchmarks

`bench/relay.rs` compares a direct connection, the bare fast-socks5 server, marksocks, and
marksocks with a mark (Linux, when marking is permitted). It measures bulk TCP echo
throughput, CONNECT latency (connect, handshake, first byte) and UDP round trips.

```sh
cargo bench --locked --bench relay
BENCH_TCP_MIB=64 BENCH_CONNECTS=200 BENCH_UDP_ROUNDS=2000 cargo bench --locked --bench relay  # quicker

# Against a running marksocks (e.g. on the router), from a LAN host. The proxy must
# accept no-auth clients. TARGET_IP is this host's address as the proxy can reach it.
MARKSOCKS_BENCH_PROXY=192.168.1.1:1080 MARKSOCKS_BENCH_TARGET_IP=192.168.1.10 \
    cargo bench --locked --bench relay
```

The figures below are medians of 3 runs, taken per column. They were measured in Linux
Docker (`--cap-add NET_ADMIN`) on an Apple-silicon Mac, over loopback, with
`BENCH_TCP_MIB=512`. **They are not router numbers.** Treat them as informational: runs
vary by about ±5%, and rows after `fast-socks5` measure about 4% lower because of their
position in the run.

| row | TCP MiB/s | CONNECT p50 µs | p99 µs | conn/s | UDP rt/s | UDP p50 µs |
|---|---:|---:|---:|---:|---:|---:|
| direct | 4079.2 | 71 | 89 | 14266 | 33899 | 28 |
| fast-socks5 | 1634.2 | 158 | 192 | 6255 | 26869 | 37 |
| marksocks | 1591.6 | 158 | 202 | 6249 | 27256 | 36 |
| marksocks+mark | 1614.2 | 158 | 207 | 6224 | 27251 | 36 |

## License

MIT, see [LICENSE](LICENSE).
