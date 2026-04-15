#!/bin/sh
systemctl daemon-reload
systemctl enable --now ssh-watcher
