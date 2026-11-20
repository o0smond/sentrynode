<h1 align="center">SentryNode</h1>

<p align="center">A lightweight, self-hosted network reconnaisance and monitoring tool.</p>

<p align="center">
  <img width="607" height="230" alt="image" src="https://github.com/user-attachments/assets/9745ff57-0038-44b3-9a04-16e8038a2736" />
</p>

---
## Overview

SentryNode is a python based terminal tool built to allow users to scan
any connected network for devices and gather information on what they
have open. Sentrynode additionally allows for analysis over time of a local network, ie
periodic scanning and diffing of those scans.

---
## Core features

-Host identification and port enumeration via TCP pinging

-Service identification via response fingerprinting and port guessing

-Structured JSON output for automation & integration with other tools

-Report generation on repeated scans of a network

---
## Tech Stack

-**Language:** Python

-**Networking:** Raw sockets/accellerated TCP connect scanning using ThreadPoolExecutor

-**Fingerprinting:** Banner analysis & port-based guessing should banner analysis fail

-**Outputs:** Formatted JSON saved in subfolders, or colored terminal reports.

-**Platform:** Linux/macOS/Windows

---
## Codebase tour

This project is split into many logical components. Here is the basic structure:

<img width="1021" height="971" alt="snode_architetcure" src="https://github.com/user-attachments/assets/7daa10b5-8933-4ed2-b919-a9e308d41270" />

**main.py:** Entry point, argument parsing, scan orchestration, etc.

**config.py**: "Settings" for the tool. User can set save directories, default ports to scan, timeouts, etc. from here

**discovery.py+portscan.py**: Host discovery (discovery.py) and port enumeration (portscan.py), both of which accellerated using ThreadPoolExecutor

**fingerprint.py**: Port banner grabbing and service derivation

**diff.py**: Compares scans (from files or memory) and reports what changed

**output.py**: JSON exporting functions

**printer.py**: Prints scans and diffs as a colored terminal report

---
## Security and design philosiphy

SentryNode is a **defence-minded tool** which focuses on allowing users to see what's going on
in their network to ensure its security. It was built of the principles of **non-intrusive scanning**
and transparency, avoiding unsafe behaviour such as raw packet abuse, brute forcing, or other general exploitation.
SentryNode interacts on a **read-only basis** with other devices on the network and provides **deterministic, explainable output**.

---
## Running the project

**Requirements:**

-Python 3.10+

**Clone the repository:**

git clone https://github.com/o0smond/sentrynode

**Install as a command (optional):**

Linux / macOS:
```bash
chmod +x main.py && ln -s "$PWD/main.py" ~/.local/bin/sentrynode
```

Windows (PowerShell, run from the repo folder, then open a new window):
```powershell
if (!(Test-Path $PROFILE)) { New-Item -Type File -Force $PROFILE }
Add-Content $PROFILE "function sentrynode { py `"$PWD\main.py`" @args }"
```

Or just run `python3 main.py` (Windows: `py main.py`) in place of `sentrynode` below.

## Usage

```
sentrynode <command> [flags]
```

| Command | What it does |
|---|---|
| `scan` | Scan the network once, or repeatedly with `-r` |
| `diff` | Compare saved scans and report what changed |
| `show` | Print saved SentryNode files as a colored report |

Run `sentrynode -h` for an overview, or `sentrynode <command> -h` for every flag.

### Examples

```
sentrynode scan                                # one light scan of your network, not saved
sentrynode scan -s 10.129.5.77 --full          # every port on one host
sentrynode scan -f                             # one scan, auto-named file in scans/
sentrynode scan -f me.json                     # one scan, saved to me.json
sentrynode scan -rfi 10 -n 7                   # 7 scans, one every 10s, auto-named series file
sentrynode scan -ri 60 -t 3600 -f me.json      # one scan a minute for an hour, into me.json
sentrynode scan -ri 60 -n 30 -d                # 30 scans, then show what changed (nothing saved)
sentrynode diff me.json                        # diff each scan in a series against the one before
sentrynode diff a.json b.json -f               # diff two single scans, auto-named file in analysis/
sentrynode show me.json                        # print a saved file as a colored report
```

### `scan` flags

| Flag | Default | Meaning |
|---|---|---|
| `-r` | off | Repeat: run a series of scans |
| `-i SEC` | `60` | Seconds from the start of one scan to the start of the next (needs `-r`) |
| `-n N` | no limit | Stop after N scans (needs `-r`) |
| `-t SEC` | no limit | Total time to keep scanning (needs `-r`) |
| `-f [NAME]` | no save | Save results. Bare `-f` auto-names the file |
| `-d` | off | Diff the series when done (needs `-r`) |
| `-s SUBNET` | your network's /24 | Subnet or single IP to scan |
| `--light` | **on** | Scan only the common ports in `config.py` |
| `--full [IP ...]` | off | Scan all 65535 ports on every found host, or only on the IPs given (slow) |
| `--json` | off | Print raw JSON instead of the report |

- `--light` and `--full` can't be used together.
- A repeat stops at `-n` or `-t`, whichever comes first. With neither, it runs until **Ctrl+C**.
- Ctrl+C keeps every finished scan, so they are still saved and diffed.
- **Interval guardrail:** `-i` must be longer than a scan takes. Values that are clearly too short are rejected before scanning. If the first scan takes longer than `-i`, the series stops and tells you the interval to use.
- `-n` must be 1 or more. `-t` and `-i` must be more than 0.

### `diff` flags

| Flag | Meaning |
|---|---|
| `FILE ...` | One series file, or 2+ single scan files, oldest first |
| `-f [NAME]` | Save the diff. Put `-f` **after** the file names |
| `--json` | Print raw JSON instead of the report |

Each scan is compared with the one before it (1→2, 2→3, …). The diff shows new and gone hosts, opened and closed ports, and service and banner changes.

### `show`

`sentrynode show FILE ...` prints any saved scan, series or diff file as a report.

### Grouped flags and subnets

- Single-letter flags can be grouped, and the last one can take a value: `-rfi 10` = `-r -f -i 10`.
- `-s` accepts `10.129.0.0/24`, `10.129.5.77/24` (becomes `10.129.5.0/24`), a single IP like `10.129.5.77` (just that host), or netmask form like `10.129.0.0/255.255.0.0`. IPv4 only.

### Output and files

- The report always prints: IPs in yellow, ports in green, values in red. In diffs, green means something appeared and red means something went away.
- Colors turn off when output is piped or `NO_COLOR` is set.
- Nothing is saved without `-f`. Bare `-f` saves to `scans/` or `analysis/` in the folder you run from, named by timestamp (`YYYY-MM-DD_HH-MM-SS.json`). `-f NAME` saves to exactly that path.
- With `scan -r -d -f NAME`, the series goes to `NAME` and the diff is auto-named in `analysis/`.
- Every file SentryNode writes starts with a `"sentrynode"` tag (`scan`, `series` or `diff`). `diff` and `show` refuse files without it.

Defaults (ports, timeouts, threads, output folders) live in `scanner/config.py`.
---
## What I learned

- **Networking fundementals:** This project immersed me in the world of networking,
  giving me practical experience with TCP handshakes, banners, ports, and how they interact
  in real networks. Building SentryNode from scratch helped me understand what’s actually happening
  in tools I use every day, from my home lab to routine web traffic.

- **Understanding a tool's internals:** Being a large tech enthusiast and linux user, I have encountered
  many CLI tools in my life. For example, when I do HTB machines, and I commonly find myself
  using tools such as netcat and nmap and such. The creation of SentryNode forced me to realize that
  a tool is pointless, no matter how well it works, if it isn't user freindly and understandable.
  Making a good tool is not an impossible task, it is a series of defined, thought-out and well implimented
  design decisions. Furthermore, by making my own terminal tool, I have gained a more thorough
  understanding of flags and argparsing for the terminal tools I use every day.

- **Using multi-threaded code:** This project was my first hands-on experience with multithreaded
  programming. After creating a prototype for this project, I realized that the scans seemed to
  take forever, and I began to wonder if there was a way I could work to speed it up.
  After some research, I learned how to use python's ThreadPoolExecutor to parallelize I/O-bound
  tasks such as discovery and port scanning. I gained insight into how concurrency can dramatically
  improve preformance in resource-heavy tasks, as well as how to balance speed with responsable
  resource use.




