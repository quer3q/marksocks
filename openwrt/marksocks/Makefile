# SPDX-License-Identifier: MIT
#
# OpenWrt package recipe for marksocks. This repository is an OpenWrt feed: add it to
# feeds.conf of an SDK or buildroot whose "packages" feed provides lang/rust, e.g.
#
#   src-git marksocks https://github.com/quer3q/marksocks.git;main
#   ./scripts/feeds update -a && ./scripts/feeds install marksocks
#   make menuconfig     # Network > Web Servers/Proxies > marksocks
#   make package/marksocks/compile V=s
#
# There is no PKG_SOURCE: the package builds the crate of the checkout it sits in (two
# directories up), like a LuCI app built from its feed. The SDK builds rust/host (rustc +
# LLVM) from source first, which takes a long time.
#
# Prebuilt switch: with MARKSOCKS_PREBUILT=/abs/path/to/marksocks in the environment of
# `scripts/feeds update/install` and `make` (it changes the package metadata), the recipe
# does not use rust at all (no rust-package.mk, no rust/host, no packages feed) and only
# packages that static binary. .github/workflows/release.yml builds the release .apk this
# way, from the musl binary its `binaries` job built with the latest stable Rust.
# Switching it on or off in an existing tree needs fresh metadata:
#   rm -rf tmp feeds/<feed>.tmp && ./scripts/feeds update -i && ./scripts/feeds install marksocks

include $(TOPDIR)/rules.mk

PKG_NAME:=marksocks
PKG_VERSION:=0.0.2
PKG_RELEASE:=1

# realpath: package/feeds/<feed>/marksocks is a symlink, and with a src-link feed so is
# feeds/<feed>, so resolve to the real openwrt/marksocks directory before going up.
MARKSOCKS_SRC:=$(realpath $(CURDIR)/../..)
# Only what `cargo install --locked` needs (bench/ and tests/ are not built). Listing them
# here also re-runs prepare/compile whenever one of them changes.
MARKSOCKS_CRATE:=$(addprefix $(MARKSOCKS_SRC)/,Cargo.toml Cargo.lock src)
PKG_FILE_DEPENDS:=$(MARKSOCKS_CRATE) $(MARKSOCKS_PREBUILT)

PKG_MAINTAINER:=Quer3q
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

ifeq ($(MARKSOCKS_PREBUILT),)
# Same as the in-tree Rust packages (procs, aardvark-dns, ...): only a target package is
# built, so no HOST_BUILD_DEPENDS. rust-package.mk passes --locked (RUST_PKG_LOCKED=1).
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1
else
# Ship the given binary byte for byte (it is already stripped: Cargo.toml strip = true).
RSTRIP:=:
endif

include $(INCLUDE_DIR)/package.mk
ifeq ($(MARKSOCKS_PREBUILT),)
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk
endif

define Package/marksocks
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=SOCKS5 proxy that can set SO_MARK on outbound sockets
  URL:=https://github.com/quer3q/marksocks
  DEPENDS:=$(RUST_ARCH_DEPENDS)
endef

define Package/marksocks/description
  Small SOCKS5 proxy (TCP CONNECT and UDP ASSOCIATE, optional username/password
  auth) built on fast-socks5. When mark is set in /etc/marksocks/config.toml,
  every destination-facing socket gets that SO_MARK, so firewall or policy
  routing rules can pick up the proxied traffic. Marking is off by default.
endef

define Package/marksocks/conffiles
/etc/config/marksocks
/etc/marksocks/config.toml
endef

# INSTALL_CONF installs with mode 0600: config.toml may hold [auth] credentials.
define Package/marksocks/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/marksocks $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/marksocks.init $(1)/etc/init.d/marksocks
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/marksocks.config $(1)/etc/config/marksocks
	$(INSTALL_DIR) $(1)/etc/marksocks
	$(INSTALL_CONF) ./files/config.toml $(1)/etc/marksocks/config.toml
endef

# Copy the crate, never target/ or .git. PKG_VERSION must equal Cargo.toml's version
# (CI checks this too, and the release tag must be v$(PKG_VERSION)).
define Build/Prepare
	grep -qx 'version = "$(PKG_VERSION)"' $(MARKSOCKS_SRC)/Cargo.toml || { \
		echo "PKG_VERSION $(PKG_VERSION) does not match $(MARKSOCKS_SRC)/Cargo.toml" >&2; exit 1; }
	$(CP) $(MARKSOCKS_CRATE) $(PKG_BUILD_DIR)/
endef

ifeq ($(MARKSOCKS_PREBUILT),)
$(eval $(call RustBinPackage,marksocks))
else
# The caller picks a binary for this package arch; nothing here can check that.
define Build/Compile
	[ -f "$(MARKSOCKS_PREBUILT)" ] || { echo "MARKSOCKS_PREBUILT=$(MARKSOCKS_PREBUILT) is not a file" >&2; exit 1; }
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/bin
	$(INSTALL_BIN) $(MARKSOCKS_PREBUILT) $(PKG_INSTALL_DIR)/bin/marksocks
endef
endif
$(eval $(call BuildPackage,marksocks))
