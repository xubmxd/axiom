#!/bin/bash
# Sync lab content to the production server and rebuild.
# Lab definitions (labs/) and target build contexts (lab-images/) are
# git-ignored on purpose — this script is how they get deployed.
#
# usage: ./sync-labs.sh [user@host] [remote-dir]
#   defaults: xubmadmin@lynx  /opt/lumen
set -e
cd "$(dirname "$0")"

DEST="${1:-xubmadmin@xubm.local}"
RDIR="${2:-/opt/lumen}"

rsync -avz --delete labs/ "$DEST:$RDIR/labs/"
rsync -avz --delete lab-images/ "$DEST:$RDIR/lab-images/"
rsync -avz --delete vpn-gateway/ "$DEST:$RDIR/vpn-gateway/"
# -t gives sudo a terminal for its password prompt over non-interactive ssh.
ssh -t "$DEST" "cd '$RDIR' && sudo docker compose up -d --build"
