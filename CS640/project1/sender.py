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

#------------------------------------------------------------------
# Class representing a Packet
class Packet:
    def __init__(self, **kwargs):
        self.type = kwargs.get("type", b'-')
        self.payload = kwargs.get("payload", "")
        self.seq = kwargs.get("sequence", 0)
        self.len = 0 if self.type != b'D' else len(self.payload)
    # Encode the Packet to transmit over network
    def encode(self):
        return struct.pack("!cII", self.type, socket.htonl(self.seq), socket.htonl(self.len)) + self.payload.encode()
    # Decode a transmitted network packet
    def decode(self, data):
        header = data[:9]
        self.payload = data[9:].decode()
        header = struct.unpack("!cII", header)
        self.type = header[0]
        self.seq = socket.ntohl(header[1])
        self.len = socket.ntohl(header[2])
    # Allow conversion into a string type for debugging
    def __str__(self):
        return f"[{self.type}|{self.seq}|{len(self.payload)}|'{self.payload}']"
    # Return full Packet type name from single character representation
    def type_str(self):
        PACKET_TYPES = {b'R' : "REQUEST", b'D' : "DATA", b'E' : "END"}
        return PACKET_TYPES.get(self.type, "UNKNOWN")

#------------------------------------------------------------------
def now():
    """Get timestamp in milliseconds"""
    return time() * 1000

#------------------------------------------------------------------
def handle_requests(args):
    """Wait and handle for an incoming request for a file"""
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.bind(('', args.my_port))

    # Variables to manage request information
    requester = None
    request = Packet()

    # Wait for a valid request packet
    while True:
        data, requester = sock.recvfrom(10240)
        request.decode(data)
        if request.type == b'R':
            break

    # Variables for sending DATA packets back to requester
    host = (requester[0], int(args.requester_port))
    seq = args.sequence_no
    delay = 1000 / args.rate
    last_packet_t = 0

    # Verify requested file exists locally
    if os.path.exists(request.payload):
        with open(request.payload, "r") as f:
            # Read requested file and send in packets
            while True:
                # Delay in between packets for packet rate limiting
                while now() - last_packet_t < delay:
                    pass
                # Read specified # bytes from file
                data = f.read(args.length)
                # If no bytes read then we are done... break out of loop
                if not data:
                    break
                # Create packet, encode, and send over network
                packet = Packet(type=b'D', sequence=seq, payload=data)
                sock.sendto(packet.encode(), host)
                send_t = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:22]
                # Display send DATA packet information
                print(
f"""{packet.type_str()} Packet
    Send Time-------: {send_t}
    Request Address-: {host[0]}:{host[1]}
    Sequence Number-: {seq}
    Payload (4B)----: '{packet.payload[:4]}'
""")
                seq += packet.len
                last_packet_t = now()
    else:
        # Requested file not found locally
        print(f"Error: File '{request.payload}' requested from {requester[0]}:{requester[1]} not found!")

    # Create final END packet, encode, and send over network
    packet = Packet(type=b'E', sequence=seq)
    sock.sendto(packet.encode(), host)
    send_t = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:22]
    # Dsiplay END packet information
    print(
f"""{packet.type_str()} Packet
    Send Time-------: {send_t}
    Request Address-: {host[0]}:{host[1]}
    Sequence Number-: {seq}
    Payload (4B)----: '{packet.payload[:4]}'
""")

    sock.close()

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="sender.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 1 : Distributed File Transfer

            Sender Program
                Works as a server that recieves a request
                for a portion of a file this program manages.
                This program will then send the file as data
                packets to the requestor via UDP.
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
        "-g",
        "--requester-port",
        metavar="<port>",
        dest="requester_port",
        action="store",
        type=int,
        required=True,
        help="Port the requesting program is listening on",
    )

    parser.add_argument(
        "-r",
        "--rate",
        metavar="<rate>",
        dest="rate",
        action="store",
        type=int,
        required=True,
        help="Number of packets sent per second",
    )

    parser.add_argument(
        "-l",
        "--length",
        metavar="<length>",
        dest="length",
        action="store",
        type=int,
        required=True,
        help="Packet payload length",
    )

    parser.add_argument(
        "-q",
        "--sequence-num",
        metavar="<seq #>",
        dest="sequence_no",
        action="store",
        type=int,
        default=0,
        help="The initial sequence of the packet exchange",
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

#------------------------------------------------------------------
def check_args(args):
    """Verify provided arguments are valid"""
    invalid_args = False
    if args.rate <= 0:
        print(f"Error: Invalid packet rate ({args.rate}) sepcified. Must be a non-zero positive integer")
        invalid_args = True

    if args.length <= 0:
        print(f"Error: Invalid packet length ({args.length}) sepcified. Must be a non-zero positive integer")
        invalid_args = True

    if args.sequence_no < 0:
        print(f"Error: Invalid sequence number ({args.sequence_no}) sepcified. Must be a positive integer")
        invalid_args = True

    if args.my_port <= 2049 or args.my_port >= 65536:
        print(f"Error: Invalid port specified ({args.my_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if args.requester_port <= 2049 or args.requester_port >= 65536:
        print(f"Error: Invalid requester port specified ({args.requester_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if invalid_args:
        sys.exit(1)

#------------------------------------------------------------------
def main():
    args = parse_args()
    check_args(args)
    handle_requests(args)

if __name__ == "__main__":
    main()
