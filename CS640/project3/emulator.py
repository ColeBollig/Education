#!/usr/bin/env python3

import sys
import os
import socket
from networking import *
from random import random
import argparse
import textwrap

__author__ = "Cole Bollig"
__email__ = "cabollig@wisc.edu"

#------------------------------------------------------------------
# Global Priority Queues
QUEUES = {
    PRIO_HIGH : [],
    PRIO_MEDIUM : [],
    PRIO_LOW : [],
}

LOG_FILE = None
LOCAL = None
VERBOSITY = 0

#------------------------------------------------------------------
def log(frame: Frame, msg: str):
    """Log a frame drop to specified log file"""
    # This local host information incase multiple emulators share the same log file
    host = LOCAL.str() if LOCAL is not None else "???.???.???.???:????"
    # Get useful frame information
    src = frame.getSrcAddr()
    dest = frame.getDestAddr()
    p_type = packet_type(frame.payload)

    line = f"{timestamp()} [{host}]: {p_type} packet from {src[0]}:{src[1]} to {dest[0]}:{dest[1]} dropped because {msg}."

    # Safety mechanism incase log file is not initialized
    if LOG_FILE is None:
        print(line)
    else:
        if VERBOSITY > 4:
            print(line)
        # Log frame drop with provided reason
        LOG_FILE.write(f"{line}\n")

#------------------------------------------------------------------
def queue(frame: Frame, table: dict, queue_size: int):
    """Queue a frame or drop if specified priority queue is full"""
    packet = frame.getPacket()
    # Drop frame if queue is full and encoded packet is not END or REQUEST type
    if len(QUEUES[frame.priority]) >= queue_size and packet.is_droppable():
        log(frame, f"{frame.prio_str()} queue is full")
    else:
        QUEUES[frame.priority].append(frame)

#------------------------------------------------------------------
def route(frame: Frame, table: dict, queue_size: int):
    """Route incoming frame if in routing table else drop frame"""
    # Check if frame's destination address is in forwarding table
    if frame.getDestAddr() in table:
        queue(frame, table, queue_size)
    else:
        log(frame, "destination address not in forwarding table")

#------------------------------------------------------------------
def get_next_frame():
    """Get the next highest priority queued frame to send"""
    frame = None

    # Check each priority queue for a frame in highest->lowest prio
    if len(QUEUES[PRIO_HIGH]) > 0:
        frame = QUEUES[PRIO_HIGH].pop(0)
        if VERBOSITY > 3:
            print(f"Next Send Frame-----: 0x{PRIO_HIGH:x} -> {frame}")
    elif len(QUEUES[PRIO_MEDIUM]) > 0:
        frame = QUEUES[PRIO_MEDIUM].pop(0)
        if VERBOSITY > 3:
            print(f"Next Send Frame-----: 0x{PRIO_MEDIUM:x} -> {frame}")
    elif len(QUEUES[PRIO_LOW]) > 0:
        frame = QUEUES[PRIO_LOW].pop(0)
        if VERBOSITY > 3:
            print(f"Next Send Frame-----: 0x{PRIO_LOW:x} -> {frame}")

    return frame

#------------------------------------------------------------------
def forward(sock: socket.socket, next_host: tuple, frame: Frame):
    """Forward a frame to the next hop (emulator or destination)"""
    if VERBOSITY > 1:
        print(f"Forwarding frame----: {frame}")
    sock.sendto(frame.encode(), next_host.addr())

#------------------------------------------------------------------
def emulate(args, table):
    """Emulate forwarding table devices (switches) to enable packet forwarding"""
    # Open log file now
    global LOG_FILE
    LOG_FILE = open(args.log_file, "a")

    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.socket_timeout)
    sock.bind(('', args.my_port))
    sock.setblocking(False)

    # Next frame to be sent with its queued up to send time for delay purposes
    next_frame = None

    # Forever loop
    while True:
        frame = None
        try:
            # Step 1: Recieve Frame
            data, requester = sock.recvfrom(10240)
            frame = Frame(data=data)
            if VERBOSITY > 1:
                print(f"Recieved frame------: {frame}")
        except BlockingIOError:
            pass

        if frame is not None:
            # Step 2: Check frame destination against forward table
            # Step 3: Queue frame by priority
            route(frame, table, args.queue_size)

        send_frame = None

        # Step 4: Check if packet delay is expired
        if next_frame is not None:
            time = next_frame[1]
            delay = table[next_frame[0].getDestAddr()][1]
            if delay > now() - time:
                continue
            send_frame = next_frame[0]
            next_frame = None
            if VERBOSITY > 2:
                print(f"Finished frame delay: {delay} -> {send_frame}")

        # Step 5: Check if packet is being delayed (if not queue one up)
        if next_frame is None:
            queue_frame = get_next_frame()
            if queue_frame is not None:
                next_frame = (queue_frame, now())

        # Step 6: Randomly determine if packet is dropped
        if send_frame is not None:
            probability = table[send_frame.getDestAddr()][2]
            packet = send_frame.getPacket()
            if packet.is_droppable() and (random() * 100) <= probability:
                log(send_frame, f"loss event occurred ({probability}%)")
                send_frame = None

        # Step 7: Send queued packet
        if send_frame is not None:
            forward(sock, table[send_frame.getDestAddr()][0], send_frame)

#------------------------------------------------------------------
def generate_forwarding_table(args):
    """Parse the specified tbale file to produce the static forwarding table"""
    table = dict()
    try:
        # Read forwarding table file
        with open(args.table_file, "r") as f:
            line_no = 0
            for line in f:
                line_no += 1
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue
                em_host, em_port, dest_host, dest_port, next_host, next_port, delay, loss_probability = line.split(" ")
                host = Host(em_host, em_port)
                if LOCAL != host:
                    continue
                dest = Host(dest_host, dest_port)
                hop = Host(next_host, next_port)
                table[dest] = (hop, int(delay), sorted([0, float(loss_probability), 100])[1])
    # Parse failure has occurred
    except Exception as e:
        print(f"Error: Failed to parse forwarding table file '{args.table_file}' (@{line_no}): {e}")
        sys.exit(1)

    # Print forwarding table
    if VERBOSITY > 0:
        title = "FORWARDING TABLE"
        print(f"{title:^67}")
        div = "+---------------------+---------------------+----------+----------+"
        print(div)
        print("|   Destination Host  |    Next Hop Host    | Delay(ms)| Loss Prob|")
        print("+=====================+=====================+==========+==========+")
        for dest, info in table.items():
            print(f"|{dest.str():^21}|{info[0].str():^21}|{info[1]:>10}|{info[2]:>9}%|")
            print(div)

    return table

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="emulator.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 2: Network Emulator and Reliable Transfer

            Emulator Program
                Emulates a network switch by recieving layer 2
                encapsulated packets to forward based on a static
                forwarding table. Each emulator will also emulate
                to unreliability of the internet by dropping
                packets in specified situations. Dropped packets
                will be logged.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-p",
        "--port",
        metavar="<port>",
        dest="my_port",
        action="store",
        type=int,
        required=True,
        help="Port this program is listening on.",
    )

    parser.add_argument(
        "-q",
        "--queue-size",
        metavar="<size>",
        dest="queue_size",
        action="store",
        type=int,
        required=True,
        help="Size of each packet forwarding queue.",
    )

    parser.add_argument(
        "-f",
        "--forwarding-table",
        metavar="<filename>",
        dest="table_file",
        action="store",
        type=str,
        required=True,
        help="File containing static forwarding table information.",
    )

    parser.add_argument(
        "-l",
        "--log",
        metavar="<filename>",
        dest="log_file",
        action="store",
        type=str,
        default="dropped-packets.log",
        help="Dropped packet logging file.",
    )

    parser.add_argument(
        "-v",
        "-verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="Increase tool output verbosity.",
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

    if args.queue_size <= 0:
        print(f"Error: Invalid queue size ({args.queue_size}) sepcified. Must be a non-zero positive integer")
        invalid_args = True

    if not os.path.exists(args.table_file):
        print(f"Error: Specified forwarding table file '{args.table_file}' does not exist.")
        invalid_args = True

    if invalid_args:
        sys.exit(1)

#------------------------------------------------------------------
def main():
    global LOCAL
    global VERBOSITY

    args = parse_args()
    check_args(args)

    # Generate global local host information
    LOCAL = get_local_host(args.my_port)
    # Set print verbosity
    VERBOSITY = args.verbosity
    # Parse static forwarding table
    table = generate_forwarding_table(args)
    # Emulate packet forwarding
    emulate(args, table)

if __name__ == "__main__":
    main()