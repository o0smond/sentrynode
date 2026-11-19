#!/usr/bin/env python3
#By: Oliver Osmond
#Created on: 2025-12-29
#Description: This file acts the main "controller" for the program, connecting
# all the files together. It reads the command line arguments and runs
# either a scan (single or repeated) or a diff of saved scans.
# Usage examples:
#   sentrynode scan                          one scan, printed, not saved
#   sentrynode scan -rfi 10 -n 7             7 scans, 10s apart, auto-named file
#   sentrynode scan -ri 5 -t 1800 -f me.json scan every 5s for 30 min into me.json
#   sentrynode diff me.json -f               diff a saved file, auto-named output

import argparse, ipaddress, json, math, sys, time
from datetime import datetime
from scanner import portscan, discovery, fingerprint, config, output, diff, printer

BANNER = "\n   ███████╗ ███████╗ ███╗   ██╗ ████████╗ ██████╗ ██╗   ██╗\n   ██╔════╝ ██╔════╝ ████╗  ██║ ╚══██╔══╝ ██╔══██╗╚██╗ ██╔╝\n   ███████╗ █████╗   ██╔██╗ ██║    ██║    ██████╔╝ ╚████╔╝ \n   ╚════██║ ██╔══╝   ██║╚██╗██║    ██║    ██╔══██╗  ╚██╔╝  \n   ███████║ ███████╗ ██║ ╚████║    ██║    ██║  ██║   ██║   \n   ╚══════╝ ╚══════╝ ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝   ╚═╝   \n\n                      SENTRYNODE\n           network scanning & change detection\n"

EXAMPLES = """examples:
  sentrynode scan                           one light scan, printed, not saved
  sentrynode scan --full -f                 all ports on every found host, auto-named file
  sentrynode scan -rfi 10 -n 7              7 scans, 10s apart, auto-named file
  sentrynode scan -ri 5 -t 1800 -f me.json  scan every 5s for 30 min into me.json
  sentrynode scan -ri 5 -n 10 -d            10 scans, then diff them
  sentrynode diff me.json -f                diff a saved file, auto-named output
  sentrynode show me.json                   print a saved file as a report

run "sentrynode scan -h", "sentrynode diff -h" or "sentrynode show -h" for every flag."""

#This function splits grouped short flags (-rfi) into single
# flags (-r -f -i). Without it argparse would read "-rfi" as
# -r with -f set to the filename "i".
def split_flags(args: list[str]) -> list[str]:
    split_args = []
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2 and arg[1:].isalpha():
            for letter in arg[1:]:
                split_args.append("-" + letter)
        else:
            split_args.append(arg)
    return split_args

#This function is an argparse type for -i and -t. It only allows
# real numbers above 0, so negative, zero, inf and nan are rejected.
def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a number")
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError(f"must be more than 0, got {value}")
    return number

#This function is an argparse type for -n. It only allows whole
# numbers of 1 or more.
def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a whole number")
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {value}")
    return number

#This function guesses the shortest time one scan of a subnet takes,
# using host discovery: each round of MAX_THREADS addresses waits
# SOCKET_TIMEOUT on every discovery port for hosts that don't answer.
#shortcut: rough floor only (a /24 guesses 4.5s, measured 4.6s on a real /24), the real limit is checked after the first scan
def min_scan_time(subnet: str) -> float:
    addresses = ipaddress.ip_network(subnet).num_addresses
    rounds = math.ceil(addresses / config.MAX_THREADS)
    return rounds * len(config.DISCOVERY_PORTS) * config.SOCKET_TIMEOUT

#This function saves a dict to JSON. -f with a name saves to that
# exact path, a bare -f saves to an auto-named file in dir.
def save(data: dict, f_arg: str | bool, dir: str):
    if f_arg == True:
        output.save_to_json(data, dir)
    else:
        output.save_to_json(data, dir, f_arg)

#This function prints results to the terminal, as a colored
# report by default or as raw JSON with --json.
def show(data: dict, args):
    if args.json:
        print(json.dumps(data, indent=4))
    else:
        printer.print_report(data)

#This function runs one scan of the given subnet and returns it as
# a tagged sentrynode scan dict. full_hosts is None for a light scan
# (common ports from config.py only), [] for a full scan of every
# found host, or a list of ips to full scan. Full scans check all
# 65535 ports, which is very resource heavy.
def scan_once(subnet: str, full_hosts: list[str] | None) -> dict:
    hosts = discovery.discover_hosts(subnet)
    hostports = portscan.scan_common_ports(hosts)

    if full_hosts == None:
        mode = "light"
        full_hosts = []
    else:
        mode = "full"
        if full_hosts == []:    #--full with no ips means every found host
            full_hosts = hosts

    for host in full_hosts:
        print(f"Scanning {host} for all open ports...")
        hostports[host] = portscan.scan_all_ports(host)

    #fingerprinting ports
    net_dict = {}

    for host in hostports:
        net_dict[host] = {}

    for host in hostports:
        for port in hostports[host]:
            data = fingerprint.fingerprint_http(host, port)
            if data == None:
                data = fingerprint.fingerprint_general(host, port)
            if data == None:
                print("An error occured while fingerprinting")
            net_dict[host][port] = data

    return {
        "sentrynode": "scan",
        "time": datetime.now().strftime("%Y-%m-%d_%H:%M:%S"),
        "subnet": subnet,
        "mode": mode,
        "results": net_dict
    }

#This function handles scan commands. It runs one scan, or with
# -r keeps scanning until -n scans are done, -t seconds have passed,
# or the user hits Ctrl+C. Then it saves (-f) and/or diffs (-d).
def cmd_scan(args, parser):
    if not args.r and (args.i != None or args.n != None or args.t != None or args.d):
        parser.error("-i, -n, -t and -d only work with -r")
    if args.i == None:
        args.i = 60    #Default interval in seconds
    
    #subnet to scan: -s if given, otherwise the network we're on
    if args.s != None:
        try:
            subnet = str(ipaddress.ip_network(args.s, strict=False))
        except ValueError:
            parser.error(f"{args.s} is not a valid subnet (example: 192.168.1.0/24)")
    else:
        try:
            subnet = discovery.local_subnet()
        except OSError:
            parser.error("could not find your network, are you connected? Use -s to give a subnet")

    #interval guardrail: don't allow -i shorter than a scan can possibly take
    if args.r and args.i < min_scan_time(subnet):
        floor = min_scan_time(subnet)
        parser.error(f"interval too short: -i {args.i:g} but scanning {subnet} takes at least {floor:g}s. Use -i {math.ceil(floor)} or more")

    #single scan
    if not args.r:
        result = scan_once(subnet, args.full)
        if args.f:
            save(result, args.f, config.OUTPUT_DIR_SCAN)
        show(result, args)
        return

    #repeated scan
    scans = []
    start = time.monotonic()
    try:
        while True:
            print(f"\nScan {len(scans) + 1}:")
            scan_start = time.monotonic()
            scans.append(scan_once(subnet, args.full))
            scan_time = time.monotonic() - scan_start
            if args.n != None and len(scans) >= args.n:
                break

            #-i is start to start, so the next scan starts -i seconds after this one started
            next_start = max(scan_start + args.i, time.monotonic())
            if args.t != None and next_start - start > args.t:  #Stop if the next scan would start after -t
                break

            #interval guardrail: a scan took longer than -i
            if scan_time > args.i:
                if len(scans) == 1:    #The first scan shows -i can never be kept, so stop instead of running back to back forever
                    print(f"\nInterval too short: one scan took {scan_time:.1f}s but -i is {args.i:g}s. Use -i {math.ceil(scan_time)} or more.")
                    break
                print(f"\nWarning: scan took {scan_time:.1f}s, longer than -i {args.i:g}s. Starting the next scan now.")

            time.sleep(max(0, next_start - time.monotonic()))   #max() because time passes between the two monotonic() calls
    except KeyboardInterrupt:
        print("\nStopped early. Keeping the scans done so far.")   #Don't lose finished scans on Ctrl+C

    if len(scans) == 0:
        print("No scans finished, nothing to save.")
        return

    series = {"sentrynode": "series", "interval": args.i, "scans": scans}
    if args.f:
        save(series, args.f, config.OUTPUT_DIR_SCAN)

    if args.d:
        if len(scans) < 2:
            print("Need at least 2 scans to diff.")
            return
        out = diff.diff_scans(scans)
        if args.f:
            output.save_to_json(out, config.OUTPUT_DIR_DIFF)
        show(out, args)    #Only the diff is shown, the full series would bury it
    else:
        show(series, args)

#This function handles "sentrynode diff". It loads each file given
# (single scans or series), puts all their scans in order, and diffs
# each scan against the one before it.
def cmd_diff(args, parser):
    scans = []
    for path in args.files:
        try:
            data = diff.load(path)
        except (OSError, ValueError) as e:   #Missing file, bad JSON, or not a sentrynode file
            parser.error(str(e))

        if data["sentrynode"] == "scan":
            scans.append(data)
        elif data["sentrynode"] == "series":
            scans.extend(data["scans"])
        else:
            parser.error(f"{path} is a {data['sentrynode']} file, not a scan file")

    if len(scans) < 2:
        parser.error("need at least 2 scans to diff (give a series file or 2+ scan files)")

    out = diff.diff_scans(scans)
    if args.f:
        save(out, args.f, config.OUTPUT_DIR_DIFF)
    show(out, args)

#This function handles "sentrynode show". It loads each saved
# sentrynode file and prints it as a report.
def cmd_show(args, parser):
    for path in args.files:
        try:
            data = diff.load(path)
        except (OSError, ValueError) as e:   #Missing file, bad JSON, or not a sentrynode file
            parser.error(str(e))
        printer.print_report(data)

#This function builds the argument parser for both subcommands.
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentrynode", description=BANNER, epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan the network once, or repeatedly with -r")
    scan.add_argument("-r", action="store_true", help="repeat the scan")
    scan.add_argument("-i", type=positive_float, metavar="SEC", help="seconds from the start of one scan to the start of the next (default 60)")
    scan.add_argument("-n", type=positive_int, metavar="N", help="number of scans")
    scan.add_argument("-t", type=positive_float, metavar="SEC", help="total time to keep scanning, in seconds")
    scan.add_argument("-f", nargs="?", const=True, metavar="NAME", help="save to file (auto-named if no NAME)")
    scan.add_argument("-d", action="store_true", help="diff the scans when done")
    scan.add_argument("-s", metavar="SUBNET", help="subnet to scan (default: your current network, as a /24)")
    scan.add_argument("--json", action="store_true", help="print raw JSON instead of the report")
    scan_type = scan.add_mutually_exclusive_group()
    scan_type.add_argument("--light", action="store_true", help="scan only the common ports in config.py (default)")
    scan_type.add_argument("--full", nargs="*", metavar="IP", help="scan all ports on every found host, or only on the IPs given (slow)")

    diff_cmd = subparsers.add_parser("diff", help="diff saved scan files")
    diff_cmd.add_argument("files", nargs="+", help="a series file, or 2+ single scan files (oldest first)")
    diff_cmd.add_argument("-f", nargs="?", const=True, metavar="NAME", help="save to file (auto-named if no NAME). Put -f after the files")
    diff_cmd.add_argument("--json", action="store_true", help="print raw JSON instead of the report")

    show_cmd = subparsers.add_parser("show", help="print saved sentrynode files as a report")
    show_cmd.add_argument("files", nargs="+", help="scan, series or diff files to print")

    return parser

parser = build_parser()
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(0)

args = parser.parse_args(split_flags(sys.argv[1:]))
if args.command == "scan":
    cmd_scan(args, parser)
elif args.command == "diff":
    cmd_diff(args, parser)
else:
    cmd_show(args, parser)
