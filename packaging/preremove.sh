#!/bin/sh
systemctl stop ssh-watcher 2>/dev/null || true
systemctl disable ssh-watcher 2>/dev/null || true
