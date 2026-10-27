#!/usr/bin/python3
"""SSH fixture server for Axiom 7.2.5 authenticated-scan labs.

Speaks genuine SSH-2 (paramiko) with password authentication: the scanner
connects with the student-supplied credentials, opens exec channels, and
retrieves system facts over real SSH. There is no VM behind it, so the
DESKTOP-system facts below are DOCUMENTED LAB FIXTURE (shaped by the
exercise: Ubuntu 21.04, kernel 5.4.0-42-generic, curl inventory), served
over a genuine encrypted, authenticated SSH transport. Finding details in
the scanner UI label this provenance explicitly.

usage: vuln-ssh-server.py <host> <port> <user>  (password via AXIOM_SSH_PW)
Prints READY <bound-port> on stdout once listening.
"""
import json
import os
import socket
import sys
import threading
import traceback

try:
    import paramiko
except ImportError:
    print("paramiko required", file=sys.stderr)
    sys.exit(2)

FIXTURE_UNAME = (
    "Linux desktop 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 "
    "x86_64 x86_64 x86_64 GNU/Linux"
)
FIXTURE_INVENTORY = {
    "hostname": "desktop",
    "os": {"name": "Ubuntu", "version": "21.04", "codename": "hirsute"},
    "kernel": "5.4.0-42-generic",
    "uname": FIXTURE_UNAME,
    "packages": {
        "curl": [
            {"version": "7.68.0-1ubuntu2.5", "usn": "USN-5079-2",
             "oses": ["Ubuntu 18.04", "Ubuntu 20.04"],
             "summary": "curl vulnerabilities fixed on earlier LTS releases"},
            {"version": "7.68.0-1ubuntu2.6", "usn": "USN-5079-1",
             "oses": ["Ubuntu 21.04"],
             "summary": "curl could be made to expose sensitive information"},
            {"version": "7.74.0-1ubuntu2", "usn": "USN-5101-1",
             "oses": ["Ubuntu 21.10"],
             "summary": "curl vulnerabilities fixed on later releases"},
        ]
    },
}


class Server(paramiko.ServerInterface):
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.command = None
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        if username == self.user and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode("utf-8", "replace")
        self.event.set()
        return True


def answer(cmd, user):
    c = cmd.strip()
    if c == "uname -a":
        return FIXTURE_UNAME + "\n", 0
    if c == "cat /etc/axiom-scan/inventory.json":
        return json.dumps(FIXTURE_INVENTORY, indent=2) + "\n", 0
    if c == "whoami":
        return user + "\n", 0
    if c == "hostname":
        return "desktop\n", 0
    if c in ("id",):
        return "uid=1001(scanner) gid=1001(scanner) groups=1001(scanner)\n", 0
    if c in ("pwd",):
        return "/home/scanner\n", 0
    if c.startswith("ls"):
        return "inventory.json\n", 0
    base = c.split()[0] if c.split() else ""
    return f"sh: {base}: command not found\n", 127


def handle(conn, user, password, host_key):
    try:
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        server = Server(user, password)
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            return
        chan = t.accept(20)
        if chan is None:
            t.close()
            return
        if not server.event.wait(20):
            chan.close()
            t.close()
            return
        out, code = answer(server.command or "", user)
        try:
            chan.send(out.encode("utf-8"))
            chan.send_exit_status(code)
        except Exception:
            pass
        try:
            chan.close()
        except Exception:
            pass
        t.close()
    except Exception:
        traceback.print_exc()


def main():
    host, port, user = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    password = os.environ.get("AXIOM_SSH_PW", "")
    if not password:
        print("AXIOM_SSH_PW is required", file=sys.stderr)
        sys.exit(2)
    host_key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(50)
    print(f"READY {sock.getsockname()[1]}", flush=True)
    while True:
        try:
            conn, _ = sock.accept()
        except Exception:
            break
        th = threading.Thread(target=handle, args=(conn, user, password, host_key), daemon=True)
        th.start()


if __name__ == "__main__":
    main()
