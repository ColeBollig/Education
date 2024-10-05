#!/usr/bin/env python3

import sys
import os
import socket
import struct
from time import time
from datetime import datetime
import argparse
import textwrap

__author__ = "Cole Bollig"
__email__ = "cabollig@wisc.edu"

TRACKER_FILE = "tracker.txt"

def now():
    return time() * 1000

class Host:
    def __init__(self, hostname, port, size):
        self.hostname = hostname
        self.host = socket.gethostbyname(hostname)
        self.port = int(port)
        self.size = int(size)
    def __str__(self) -> str:
        return f"{self.hostname}({self.host}:{self.port}) | {self.size}"
    def addr(self) -> tuple:
        return (self.host, self.port)

class Packet:
    def __init__(self, **kwargs):
        self.type = kwargs.get("type", b'-')
        self.payload = kwargs.get("payload", "")
        self.seq = kwargs.get("sequence", 0)
        self.len = 0 if self.type != b'D' else len(self.payload)
    def encode(self):
        return struct.pack("!cII", self.type, socket.htonl(self.seq), socket.htonl(self.len)) + self.payload.encode()
    def decode(self, data):
        header = data[:9]
        self.payload = data[9:].decode()
        header = struct.unpack("!cII", header)
        self.type = header[0]
        self.seq = socket.ntohl(header[1])
        self.len = socket.ntohl(header[2])
    def __str__(self):
        return f"[{str(self.type)}|{self.seq}|{len(self.payload)}|'{self.payload}']"
    def type_str(self):
        PACKET_TYPES = {b'R' : "REQUEST", b'D' : "DATA", b'E' : "END"}
        return PACKET_TYPES.get(self.type, "UNKNOWN")

class Summary:
    def __init__(self, host, port, expected):
        self.host = host
        self.port = port
        self.start_t = now()
        self.end_t = None
        self.last_t = None
        self.num_data_packets = 0
        self.bytes_rec = 0
        self.bytes_expected = expected
    def count(self, b: int):
        self.num_data_packets += 1
        self.bytes_rec += b
    def finished(self):
        self.end_t = now()
    def percent(self):
        return (self.bytes_rec / self.bytes_expected) * 100
    def __str__(self):
        total_t = self.end_t - self.start_t
        packets_per_sec = round(self.num_data_packets / (total_t / 1000))
        return (
f"""SUMMARY
    Sender Address-------: {self.host}:{self.port}
    Total Data Packets---: {self.num_data_packets}
    Total Bytes Revieved-: {self.bytes_rec}B (Expected {self.bytes_expected}B)
    Avg Packets/Second---: {packets_per_sec} p/s
    Test Duration--------: {total_t:.2f} ms
""")

def request_files(args, tracker):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.bind(('', args.my_port))

    for filename in args.files:
        f = open(filename, "w")
        request = Packet(type=b'R', payload=filename)
        for sender in tracker[filename].values():
            result = None
            sock.sendto(request.encode(), sender.addr())
            while True:
                percentage = ""
                packet = Packet()
                data, host = sock.recvfrom(10240)
                if result is None:
                    result = Summary(host[0], host[1], sender.size)
                recieve_t = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:22]
                packet.decode(data)
                if packet.type == b'D':
                    result.count(packet.len)
                    percentage = f"\n    Data Recieved---: {result.percent():.2f}%"
                f.write(packet.payload)
                print(
f"""{packet.type_str()} Packet
    Recieve Time----: {recieve_t}
    Sender Address--: {host[0]}:{host[1]}
    Sequence Number-: {packet.seq}
    Length----------: {packet.len}
    Payload (4B)----: '{packet.payload[:4]}'{percentage}
""")
                if packet.type == b'E':
                    result.finished()
                    break
            print(f"{result}")
        f.close()
    sock.close()
    return

def get_tracking_info():
    if not os.path.exists(TRACKER_FILE):
        print(f"Error: File tracking file '{TRACKER_FILE}' not found near requester.py")
        sys.exit(1)

    TRACKER = dict()

    with open(TRACKER_FILE, "r") as f:
        for line in f:
            filename, ID, hostname, port, size = line.strip().split(" ")
            #print(f"Parsed: '{filename}' '{ID}' '{hostname}' '{port}' '{size}'")
            if filename in TRACKER:
                if ID in TRACKER[filename]:
                    print(f"Error: Invalid tracking information. ID {ID} specified multiple times")
                    sys.exit(1)
            else:
                TRACKER[filename] = dict()
            file_portion = { ID : Host(hostname, port, size.replace("B", "")) }
            TRACKER[filename].update(file_portion)

    # Sort per file sender sequence for further use
    for filename, info in TRACKER.items():
        sorted_info = {ID : info[ID] for ID in sorted(info.keys())}
        TRACKER[filename] = sorted_info

    return TRACKER

def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="sender.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 1 : Distributed File Transfer

            Requester Program
                Provided files, the requester program will
                reach out to Sender programs (in order) to
                retrieve specified files. Files and what senders
                to request portions from is specified in
                tracker.txt.
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
        "-t",
        "--timeout",
        metavar="<sec>",
        dest="timeout",
        action="store",
        type=int,
        default=None,
        help="Socket timeout value if specified else None",
    )

    return parser.parse_args()

def check_args(args, tracker):
    invalid_args = False

    if args.my_port <= 2049 or args.my_port >= 65536:
        print(f"Error: Invalid port specified ({args.my_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    for filename in args.files:
        if filename not in tracker:
            print(f"Error: Specified file '{filename}' not found in '{TRACKER_FILE}'")
            invalid_args = True

    if invalid_args:
        sys.exit(1)

def main():
    args = parse_args()
    tracker = get_tracking_info()
    check_args(args, tracker)
    request_files(args, tracker)

if __name__ == "__main__":
    main()
