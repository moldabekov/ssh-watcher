#!/bin/sh
set -e

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
SYSTEMDDIR="${SYSTEMDDIR:-/usr/lib/systemd/system}"

# Find binary (release > dev build)
if [ -f "zig-out/release/ssh-watcher-x86_64-linux-static" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux-static"
elif [ -f "zig-out/release/ssh-watcher-x86_64-linux" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux"
elif [ -f "zig-out/bin/ssh-watcher" ]; then
    BIN_SRC="zig-out/bin/ssh-watcher"
else
    echo "Error: no binary found. Run 'zig build' or 'zig build release' first." >&2
    exit 1
fi

install -Dm755 "$BIN_SRC" "$DESTDIR$PREFIX/bin/ssh-watcher"
install -Dm644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
install -Dm644 config/ssh-watcher.service "$DESTDIR$SYSTEMDDIR/ssh-watcher.service"

if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "Installed ssh-watcher"
echo "  Binary:  $DESTDIR$PREFIX/bin/ssh-watcher"
echo "  Config:  $DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
echo "  Service: $DESTDIR$SYSTEMDDIR/ssh-watcher.service"
echo ""
echo "Start: sudo systemctl enable --now ssh-watcher"
