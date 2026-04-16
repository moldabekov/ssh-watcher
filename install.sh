#!/bin/sh
set -e

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
OS="$(uname -s)"

# Select binary. Linux tries static -> dynamic -> dev. macOS picks the
# architecture matching the host (`uname -m`) so Intel Macs don't end up
# with an aarch64 binary that silently fails to launch.
case "$OS" in
  Linux)
    if [ -f "zig-out/release/ssh-watcher-x86_64-linux-static" ]; then
        BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux-static"
    elif [ -f "zig-out/release/ssh-watcher-x86_64-linux" ]; then
        BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux"
    elif [ -f "zig-out/bin/ssh-watcher" ]; then
        BIN_SRC="zig-out/bin/ssh-watcher"
    else
        echo "Error: no Linux binary found. Run 'zig build' or 'zig build release' first." >&2
        exit 1
    fi
    ;;
  Darwin)
    ARCH="$(uname -m)"
    case "$ARCH" in
      arm64|aarch64) MAC_BIN="ssh-watcher-aarch64-macos" ;;
      x86_64)        MAC_BIN="ssh-watcher-x86_64-macos" ;;
      *)
        echo "Error: unsupported macOS arch: $ARCH" >&2
        exit 1
        ;;
    esac
    if [ -f "zig-out/release/$MAC_BIN" ]; then
        BIN_SRC="zig-out/release/$MAC_BIN"
    elif [ -f "zig-out/bin/ssh-watcher" ]; then
        BIN_SRC="zig-out/bin/ssh-watcher"
    else
        echo "Error: no macOS binary found (expected zig-out/release/$MAC_BIN). Run 'zig build release-macos' first." >&2
        exit 1
    fi
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

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
    PLIST_NAME="com.moldabekov.ssh-watcher.plist"

    install -d "$DESTDIR$BINDIR"
    install -m 755 "$BIN_SRC" "$DESTDIR$BINDIR/ssh-watcher"

    install -d "$DESTDIR$SYSCONFDIR/ssh-watcher"
    install -m 644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"

    # Rewrite ProgramArguments path with the actual $BINDIR so a custom
    # BINDIR override doesn't leave the plist pointing at /usr/local/bin.
    install -d "$DESTDIR$PLISTDIR"
    sed "s|/usr/local/bin/ssh-watcher|$BINDIR/ssh-watcher|g" \
        "config/$PLIST_NAME" > "$DESTDIR$PLISTDIR/$PLIST_NAME"
    chmod 644 "$DESTDIR$PLISTDIR/$PLIST_NAME"

    # Ad-hoc codesign is required on Apple Silicon — unsigned Mach-O binaries
    # are killed by the kernel at exec time ("Killed: 9"). This is not optional.
    # Skip only when staging into a $DESTDIR (packaging flow) — the installer
    # target should sign the binary at its final path.
    if [ -z "$DESTDIR" ]; then
        if command -v codesign >/dev/null 2>&1; then
            codesign --sign - --force "$BINDIR/ssh-watcher"
        else
            echo "warning: codesign not found; on Apple Silicon the binary will not launch" >&2
        fi
    fi

    echo "Installed ssh-watcher (macOS/launchd)"
    echo "  Binary:  $DESTDIR$BINDIR/ssh-watcher"
    echo "  Config:  $DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    echo "  Service: $DESTDIR$PLISTDIR/$PLIST_NAME"
    echo ""
    echo "Start:     sudo launchctl bootstrap system $PLISTDIR/$PLIST_NAME"
    echo "Restart:   sudo launchctl kickstart -k system/com.moldabekov.ssh-watcher"
    echo "Stop:      sudo launchctl bootout system/com.moldabekov.ssh-watcher"
    echo ""
    echo "Note: osascript desktop notifications from a LaunchDaemon require extra"
    echo "      plumbing (launchctl asuser ...). Expect notifications to be silent"
    echo "      in the default root-daemon configuration."
    ;;
esac
