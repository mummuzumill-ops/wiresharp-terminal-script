# Vite Shop Terminal Script

One-command installer for the **NetScope capture agent**. No manual download, no `python3 capture_agent.py` path juggling — clone and run in a single line.

## Quick start

On the machine whose traffic you want to watch:

```bash
curl -fsSL https://raw.githubusercontent.com/mummuzumill-ops/wiresharp-terminal-script/main/install.sh | sudo bash -s -- --room NET-XXXXX-XXXXX
```

Replace `NET-XXXXX-XXXXX` with the room code shown in the NetScope web app (Remote session panel → the code in the toolbar → **Copy command**).

`sudo` is required because packet capture needs raw socket access. The installer re-exits with a clear message if you forget it.

## What it does

1. Clones this repo to `~/.wiresharp-terminal-script` (or reuses an existing checkout with `git pull`).
2. Marks `capture_agent.py` executable.
3. Runs it with whatever flags you passed through, e.g. `--room`, `--iface`, `--port`.

It is **Python-stdlib-only** on Linux (AF_PACKET). macOS/Windows fall back to Scapy if installed; Windows additionally needs [Npcap](https://npcap.com).

## Manual usage

```bash
git clone https://github.com/mummuzumill-ops/wiresharp-terminal-script.git
cd wiresharp-terminal-script
sudo python3 capture_agent.py --room NET-XXXXX-XXXXX
```

Other flags:

```bash
sudo python3 capture_agent.py                     # auto-detect interface, local port 9000
sudo python3 capture_agent.py --iface eth0
python3 capture_agent.py --port 9443
python3 capture_agent.py --test                   # demo frames, no root needed
```

## Environment overrides

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETSCOPE_REPO_URL` | this repo | Clone source |
| `NETSCOPE_DIR` | `~/.wiresharp-terminal-script` | Install location |

## Part of NetScope

The main application lives in the `wiresharp` repo. This repo ships only the installer and the capture agent so the clone-and-run path stays a single command.
