<h1 align="center">SentryNode</h1>

<p align="center">A lightweight, self-hosted network reconnaisance and monitoring tool.</p>

<p align="center">
  <img width="607" height="230" alt="image" src="https://github.com/user-attachments/assets/9745ff57-0038-44b3-9a04-16e8038a2736" />
</p>

---
## Overview

SentryNode is a python based program built to allow users to scan
their local netowrk for devices and gather information on what they
have open (port-wise), as well as to allow for analysis over time of a local network.
This program was built both to allow me and other users with 
greater modularity than something like nmap, and for my learning.

---
## Core features

-Host identification and port enumeration via TCP "pinging"

-Service identification via response fingerprinting

-Structured JSON output for both automation and user ease/storage

-Difference based scan comparison of said JSONs

---
## Tech Stack

-**Language:** Python

-**Networking:** Raw sockets/accellerated TCP connect scanning using ThreadPoolExecutor

-**Fingerprinting:** Banner analysis & port-based guessing should banner analysis fail

-**Data Format:** JSON scan artifacts

<img width="300" height="400" alt="image" src="https://github.com/user-attachments/assets/65cf3fc1-a6d0-4633-95c2-04dded34257f" />

-**Platform:** Linux-first, POSIX-compliant

---
## Codebase tour

This project is split into many logical components. Here is the basic structure:

<img width="300" height="202" alt="image" src="https://github.com/user-attachments/assets/6d824ac5-e133-432f-83e2-72cff4e81c97" />

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

-Linux or WSL (reccomended)

**Clone the repository:**

git clone https://github.com/o0smond/sentrynode

**Install as a command (optional):**

```bash
chmod +x main.py && ln -s "$PWD/main.py" ~/.local/bin/sentrynode
```

Or just run `python3 main.py` in place of `sentrynode` below.

**Usage:**

```
sentrynode scan                          # one scan, printed, not saved
sentrynode scan -f                       # one scan, auto-named file in scans/
sentrynode scan -f me.json               # one scan, saved to me.json
sentrynode scan -rfi 10 -n 7             # 7 scans, 10s apart, auto-named series file
sentrynode scan -ri 5 -t 1800 -f me.json # scan every 5s for 30 minutes, into me.json
sentrynode scan -ri 5 -n 10 -d           # 10 scans, then diff them (nothing saved)
sentrynode diff me.json                  # diff each scan in a series against the one before
sentrynode diff a.json b.json -f         # diff two single scans, auto-named file in analysis/
sentrynode show me.json                  # print a saved file as a colored report
```

**scan flags:** `-r` repeat, `-i SEC` time from the start of one scan to the start of the next (default 60, must be longer than a scan takes), `-n N` number of scans,
`-t SEC` total time, `-f [NAME]` save to file, `-d` diff when done, `-s SUBNET` subnet
(default: the /24 of the network you're on), `--light` common ports
from config.py only (default), `--full [IP ...]` all ports on every found host, or only the IPs given (slow).

**diff flags:** `-f [NAME]` save to file. Put `-f` after the file names.

`scan` and `diff` always print a colored report (ips yellow, ports green, values red).
Add `--json` to print raw JSON instead, e.g. for piping into other tools.

Defaults (ports, timeouts, threads, output folders) live in `scanner/config.py`.
Every file SentryNode writes has a `"sentrynode"` tag at the top (`scan`, `series` or `diff`),
and `diff` refuses files without it.

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
  design decisions.

- **Using multi-threaded code:** This project was my first hands-on experience with multithreaded
  programming. After creating a prototype for this project, I realized that the scans seemed to
  take forever, and I began to wonder if there was a way I could work to speed it up.
  After some research, I learned how to use python's ThreadPoolExecutor to parallelize I/O-bound
  tasks such as discovery and port scanning. I gained insight into how concurrency can dramatically
  improve preformance in resource-heavy tasks, as well as how to balance speed with responsable
  resource use.




