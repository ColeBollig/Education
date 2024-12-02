#!/usr/bin/env python3

import sys
import os
import socket
from networking import *
import argparse
import textwrap

__author__ = "Cole Bollig"
__email__ = "cabollig@wisc.edu"

TRACKER_FILE = "tracker.txt"

#------------------------------------------------------------------
# Class to collect data transfer information from remote sender
class Summary:
    def __init__(self, addr: tuple):
        self.host = addr[0]
        self.port = addr[1]
        self.start_t = now()
        self.end_t = None
        self.done = False
        self.last_t = None
        self.num_data_packets = 0
        self.bytes_rec = 0
    def packet(self):
        self.num_data_packets += 1
    # Count bytes recieved from sender and increment number of recieved data packets
    def count(self, b: int):
        self.num_data_packets += 1
        self.bytes_rec += b
    # Mark that sender sent END packet
    def finished(self):
        self.end_t = now()
        self.done = True
    # Convert to string to display summary output
    def __str__(self):
        total_t = self.end_t - self.start_t
        packets_per_sec = round((self.num_data_packets / (total_t / 1000)))
        return (
f"""SUMMARY
    Sender Address-------: {self.host}:{self.port}
    Total Data Packets---: {self.num_data_packets}
    Total Bytes Revieved-: {self.bytes_rec}B
    Avg Packets/Second---: {packets_per_sec} p/s
    Test Duration--------: {total_t:.2f} ms
""")

#------------------------------------------------------------------
def acknowledgement(sock: socket.socket, addr: tuple, src: tuple, dest: tuple, seq: int):
    """Send acknowledgment to sending host"""
    send_frame(sock, addr, src, dest, Packet(type=P_ACK, sequence=seq))

#------------------------------------------------------------------
def request_files(args, tracker):
    """Retrieve requested files from senders"""
    # setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.socket_timeout)
    sock.bind(('', args.my_port))

    sock.setblocking(False)

    # Set up local host and forwarding emulator host information
    local = get_local_host(args.my_port)
    forward = Host(args.forward_host, args.forward_port)
    send_frame(sock, forward.addr(), local.addr(), forward.addr(), Packet(type=P_HELLO))

    # Retrieve each specified file
    for filename in args.files:
        # Create request packet to send to each Sender
        request = Packet(type=P_REQUEST, payload=filename, length=args.window)
        # Setup summary result per sender
        results = {sender.addr() : Summary(sender.addr()) for sender in tracker[filename].values()}
        # Setup data structure to hold recieved data packets per sender
        packets = {sender.addr() : dict() for sender in tracker[filename].values()}

        # Send request packet to each sender
        for sender in tracker[filename].values():
            # Send request for sender
            send_frame(sock, forward.addr(), local.addr(), sender.addr(), request)

        # Listen on socket for DATA->END packets
        while True:
            try:
                # Check if all senders have sent an END packet
                done = sum([int(result.done) for result in results.values()])
                if done == len(results):
                    break

                # Recieve a data
                data, remote = sock.recvfrom(10240)
                # Decode tramsitted frame
                frame = Frame(data=data)
                # Verify this frame belongs here (i.e. dest host equals local host)
                assert frame.getDestAddr() == local.addr()
                # Get frame source address
                src_addr = frame.getSrcAddr()
                # Extract inner packet from fram
                packet = frame.getPacket()

                # If END packet: display, update and print summary
                if packet.is_end():
                    packet.display(src_addr)
                    results[src_addr].finished()
                    print(str(results[src_addr]))
                # If DATA packet: send ack, check if already stored (store if not already recieved)
                elif packet.is_data():
                    acknowledgement(sock, forward.addr(), local.addr(), src_addr, packet.seq)
                    if packet.seq not in packets[src_addr]:
                        packets[src_addr][packet.seq] = packet
                        results[src_addr].count(packet.len)
                    else:
                        results[src_addr].packet()

            except BlockingIOError:
                pass

        # Write all data packets (Sender order: Sequence order)
        with open(filename, "w") as f:
            for host, portion in packets.items():
                order = sorted(portion.keys())
                portion = {seq : portion[seq] for seq in order}
                for packet in portion.values():
                    #packet.display(host)
                    f.write(packet.payload)
    sock.close()

#------------------------------------------------------------------
def get_tracking_info():
    """Parse tracker file for where to make requests for files"""
    # Check if the tracker file exists locally (fail if not)
    if not os.path.exists(TRACKER_FILE):
        print(f"Error: File tracking file '{TRACKER_FILE}' not found near requester.py")
        sys.exit(1)

    TRACKER = dict()

    # Read the tracker file
    with open(TRACKER_FILE, "r") as f:
        line_no = 0
        for line in f:
            line_no += 1
            line = line.strip()
            if line == "" or line[0] == "#":
                continue
            try:
                filename, ID, hostname, port = line.strip().split(" ")
                #print(f"Parsed: '{filename}' '{ID}' '{hostname}' '{port}'")
                if filename in TRACKER:
                    if ID in TRACKER[filename]:
                        raise RuntimeError(f"ID {ID} specified multiple times")
                else:
                    TRACKER[filename] = dict()
                file_portion = { ID : Host(hostname, port) }
                TRACKER[filename].update(file_portion)
            except Exception as e:
                print(f"Error: Failed to parse {TRACKER_FILE} (@{line_no}): {e}")
                sys.exit(1)

    # Sort per file sender sequence for further use
    for filename, info in TRACKER.items():
        sorted_info = {ID : info[ID] for ID in sorted(info.keys())}
        TRACKER[filename] = sorted_info

    return TRACKER

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="requester.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 3: Link State Protocol and Trace Route

            Requester Program
                Provided files, the requester program will
                reach out to Sender programs (in order) to
                retrieve specified files. Files and what senders
                to request portions from is specified in
                {TRACKER_FILE}.
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
        help="Port this program is listening on",
    )

    parser.add_argument(
        "-o",
        "--file",
        metavar="<filename>",
        dest="files",
        action="append",
        required=True,
        help="File to request from senders",
    )

    parser.add_argument(
        "-f",
        "--forward-host",
        metavar="<hostname>",
        dest="forward_host",
        action="store",
        type=str,
        required=True,
        help="Host name of initial packet forwarding emulator",
    )

    parser.add_argument(
        "-e",
        "--forward-port",
        metavar="<port>",
        dest="forward_port",
        action="store",
        type=int,
        required=True,
        help="Port of initial packet forwarding emulator",
    )

    parser.add_argument(
        "-w",
        "--window",
        metavar="<size>",
        dest="window",
        action="store",
        type=int,
        default=10,
        help="Number of packets per sending window",
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
def check_args(args, tracker):
    """Verify provided arguments are valid"""
    invalid_args = False

    if not is_valid_port(args.my_port):
        print(f"Error: Invalid port specified ({args.my_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if not is_valid_port(args.forward_port):
        print(f"Error: Invalid emulator port specified ({args.forward_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    for filename in args.files:
        if filename not in tracker:
            print(f"Error: Specified file '{filename}' not found in '{TRACKER_FILE}'")
            invalid_args = True

    if invalid_args:
        sys.exit(1)

#------------------------------------------------------------------
def main():
    args = parse_args()
    tracker = get_tracking_info()
    check_args(args, tracker)
    request_files(args, tracker)

if __name__ == "__main__":
    main()
