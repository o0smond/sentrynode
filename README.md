# SentryNode

A lightweight, self-hosted network reconnaisance and monitoring tool.

<img width="607" height="230" alt="image" src="https://github.com/user-attachments/assets/9745ff57-0038-44b3-9a04-16e8038a2736" />

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

**config.py**: "Settings" for the tool. User can set save directories, default ports to scan, the target subnet, etc. from here

**discovery.py+portscan.py**: Host discovery (discovery.py) and port enumeration (portscan.py), both of which accellerated using ThreadPoolExecutor

**fingerprint.py**: Port banner grabbing and service derivation

**diff.py**: JSON analysis functions for analysis mode

**output.py**: JSON exporting functions

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

**Run the program:**

python main.py

**or** 

python3 main.py

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




