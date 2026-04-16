#!/bin/sh
set -e

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
OS="$(uname -s)"

# Find binary (release > dev build). Pattern matches both Linux and macOS
# targets so the same script works after `zig build release` or `release-macos`.
if [ -f "zig-out/release/ssh-watcher-x86_64-linux-static" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux-static"
elif [ -f "zig-out/release/ssh-watcher-x86_64-linux" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux"
elif [ -f "zig-out/release/ssh-watcher-aarch64-macos" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-aarch64-macos"
elif [ -f "zig-out/release/ssh-watcher-x86_64-macos" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-macos"
elif [ -f "zig-out/bin/ssh-watcher" ]; then
    BIN_SRC="zig-out/bin/ssh-watcher"
else
    echo "Error: no binary found. Run 'zig build', 'zig build release', or 'zig build release-macos' first." >&2
    exit 1
fi

case "$OS" in
  Linux)
    BINDIR="$PREFIX/bin"
    SYSTEMDDIR="${SYSTEMDDIR:-/usr/lib/systemd/system}"

    install -Dm755 "$BIN_SRC" "$DESTDIR$BINDIR/ssh-watcher"
    install -Dm644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    install -Dm644 config/ssh-watcher.service "$DESTDIR$SYSTEMDDIR/ssh-watcher.service"

    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi

    echo "Installed ssh-watcher (Linux/systemd)"
    echo "  Binary:  $DESTDIR$BINDIR/ssh-watcher"
    echo "  Config:  $DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    echo "  Service: $DESTDIR$SYSTEMDDIR/ssh-watcher.service"
    echo ""
    echo "Start: sudo systemctl enable --now ssh-watcher"
    ;;

  Darwin)
    BINDIR="${BINDIR:-/usr/local/bin}"
    PLISTDIR="/Library/LaunchDaemons"

    install -d "$DESTDIR$BINDIR"
    install -m 755 "$BIN_SRC" "$DESTDIR$BINDIR/ssh-watcher"

    install -d "$DESTDIR$SYSCONFDIR/ssh-watcher"
    install -m 644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"

    install -d "$DESTDIR$PLISTDIR"
    install -m 644 config/com.moldabekov.ssh-watcher.plist "$DESTDIR$PLISTDIR/com.moldabekov.ssh-watcher.plist"

    # Ad-hoc codesign avoids "cannot be opened because the developer cannot
    # be verified" Gatekeeper warnings for binaries built via cross-compile.
    # Skips silently if the binary is already signed or codesign is absent.
    if [ -z "$DESTDIR" ] && command -v codesign >/dev/null 2>&1; then
        codesign --sign - --force "$BINDIR/ssh-watcher" 2>/dev/null || true
    fi

    echo "Installed ssh-watcher (macOS/launchd)"
    echo "  Binary:  $DESTDIR$BINDIR/ssh-watcher"
    echo "  Config:  $DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    echo "  Service: $DESTDIR$PLISTDIR/com.moldabekov.ssh-watcher.plist"
    echo ""
    echo "Start: sudo launchctl load $PLISTDIR/com.moldabekov.ssh-watcher.plist"
    ;;

  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac
