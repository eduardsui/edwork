#!/usr/bin/env bash

DIR="$(cd "$(dirname "$0")" && pwd)"
$DIR/edfs_mount -dir "$HOME/edfs" -gui
