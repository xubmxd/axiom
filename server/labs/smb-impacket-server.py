#!/usr/bin/python3
"""Multi-share impacket SMB server for local-provider Axiom SMB labs.

One process serves every share of one lab IP on TCP/445 (a single bind),
so multi-share hosts (dc01, the alfred host) never contend with themselves.

usage: smb-impacket-server.py <listen-ip> <workdir>
  <workdir>/shares.json: [{name, path, comment}, ...]  (written by smb-range.js)
"""
import json
import os
import sys


def main():
    ip, workdir = sys.argv[1], sys.argv[2]
    with open(os.path.join(workdir, "shares.json"), encoding="utf-8") as f:
        specs = json.load(f)
    from impacket.smbserver import SimpleSMBServer

    server = SimpleSMBServer(listenAddress=ip, listenPort=445)
    for spec in specs:
        server.addShare(spec["name"], spec["path"], shareComment=spec.get("comment", ""))
    server.setSMB2Support(True)
    server.start()


if __name__ == "__main__":
    main()
