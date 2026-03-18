#!/bin/bash
set -e

systemctl stop azlo-linux-watch 2>/dev/null || true
systemctl disable azlo-linux-watch 2>/dev/null || true
