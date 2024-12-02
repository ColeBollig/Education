#!/usr/bin/env python3

import sys
import os
import socket
from networking import *
import argparse
import textwrap

__author__ = "Cole Bollig"
__email__ = "cabollig@wisc.edu"

#------------------------------------------------------------------
def trace_route(args):
    """Trace packet route between specified emulators"""

    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.socket_timeout)
    sock.bind(('', args.my_port))

    # Create host variables for this program and the start and end emulators
    local = get_local_host(args.my_port)
    start = Host(args.start_host, args.start_port)
    end = Host(args.end_host, args.end_port)

    # Initial ttl is 0
    ttl = 0

    print(f"Tracing Sortest Path from {start.str()} to {end.str()}")

    while True:
        # Create trace packet
        trace = Packet(type=P_TRACE, sequence=ttl)

        # Debug sending packet information
        if args.debug > 0:
            print(f"DEBUGGING (send): Source={local.str()} Dest={end.str()} TTL={ttl}")

        # Send trace packet to start emulator
        send_frame(sock, start.addr(), local.addr(), end.addr(), trace)

        # Recieve a frame
        data, remote = sock.recvfrom(10240)
        # Decode tramsitted frame
        frame = Frame(data=data)

        # Get src and destination addresses
        src = frame.getSrcAddr()
        dest = frame.getDestAddr()

        # Verify this frame belongs here (i.e. dest host equals local host)
        assert dest == local

        # Debug receiving a packet
        if args.debug > 0:
            packet = frame.getPacket()
            print(f"DEBUGGING (received): Source={src[0]}:{src[1]} Dest={dest[0]}:{dest[1]} TTL={packet.seq}")

        # Output hop information
        hop = ttl + 1
        print(f"   [{hop}] > {src[0]}:{src[1]}")

        # If returned packet source is end emulator break
        if src == end:
            break

        # Increase TTL for next route packet
        ttl += 1

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="emulator.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 3: Link State Protocol and Trace Route

            Trace Route Program
                Trace the shortest path route between two
                specififed emulators.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-a",
        "--port",
        metavar="<port>",
        dest="my_port",
        action="store",
        type=int,
        required=True,
        help="Port this program is listening on.",
    )

    parser.add_argument(
        "-b",
        "--start-host",
        metavar="<hostname>",
        dest="start_host",
        action="store",
        type=str,
        required=True,
        help="Host name of starting emulator to trace route from.",
    )

    parser.add_argument(
        "-c",
        "--start-port",
        metavar="<port>",
        dest="start_port",
        action="store",
        type=int,
        required=True,
        help="Port of starting emulator to trace route from.",
    )

    parser.add_argument(
        "-d",
        "--end-host",
        metavar="<hostname>",
        dest="end_host",
        action="store",
        type=str,
        required=True,
        help="Host name of end emulator to trace route to.",
    )

    parser.add_argument(
        "-e",
        "--end-port",
        metavar="<port>",
        dest="end_port",
        action="store",
        type=int,
        required=True,
        help="Port of end emulator to trace route to.",
    )

    parser.add_argument(
        "-f",
        "--debug",
        metavar="<level>",
        dest="debug",
        action="store",
        type=int,
        default=0,
        help="Debug level (0|1)",
    )

    parser.add_argument(
        "-z",
        "--socket-timeout",
        metavar="<sec>",
        dest="socket_timeout",
        action="store",
        type=int,
        default=None,
        help="Socket timeout value if specified else None",
    )

    return parser.parse_args()

#------------------------------------------------------------------
def check_args(args):
    """Verify provided arguments are valid"""
    invalid_args = False
    if not is_valid_port(args.my_port):
        print(f"Error: Invalid port specified ({args.my_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if not is_valid_port(args.start_port):
        print(f"Error: Invalid port specified ({args.start_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if not is_valid_port(args.end_port):
        print(f"Error: Invalid port specified ({args.end_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if args.debug < 0:
        print(f"Error: Invalid debug level {args.debug}. Non-positive integer")
        invalid_args = True

    if invalid_args:
        sys.exit(1)

#------------------------------------------------------------------
def main():
    args = parse_args()
    check_args(args)
    trace_route(args)

if __name__ == "__main__":
    main()
