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
def create_packet(f, size: int, seq: int) -> Packet:
    """Parse file to create a data packets"""
    data = f.read(size)
    return None if not data else Packet(type=P_DATA, payload=data, sequence=seq)

#------------------------------------------------------------------
def handle_requests(args):
    """Wait and handle for an incoming request for a file"""
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.socket_timeout)
    sock.bind(('', args.my_port))

    # Variables to manage request information
    requester = None
    request = None

    # Wait for a valid request packet
    while True:
        data, requester = sock.recvfrom(10240)
        frame = Frame(data=data)
        request = frame.getPacket()
        if request.type == P_REQUEST:
            break

    sock.setblocking(False)

    # Variables for sending DATA packets back to requester
    local = get_local_host(args.my_port)
    forward_addr = (socket.gethostbyname(args.forward_host), args.forward_port)
    dest = (requester[0], int(args.requester_port))
    sent_packets = 0
    dropped_packets = 0
    last_packet_t = 0
    seq = 0

    # Verify requested file exists locally
    if os.path.exists(request.payload):
        with open(request.payload, "r") as f:
            window = {}
            # Parse initial window packets (up to window size)
            for i in range(request.len):
                seq += 1
                packet = create_packet(f, args.length, seq)
                if packet is not None:
                    window[seq] = (packet, 0, 0, False)
                else:
                    break

            # Read requested file and send in packets
            while len(window) > 0:
                finished = []
                # Manage packets in window
                for key, info in window.items():
                    packet, attempt, time, failed = info
                    # Check transmission timeout (None for initial sending)
                    if not failed and args.timeout <= now() - time:
                        attempt += 1
                        # Check if packet has been attempted the max number of times
                        if attempt > args.attempts:
                            # Print error and mark as failed
                            print(f"Error: Failed to send packet #{packet.seq} to {dest[0]}:{dest[1]} after {args.attempts} attempts.")
                            failed = True
                        else:
                            # Delay packet for sending rate
                            last_packet_t = delay(args.rate, last_packet_t)
                            send_frame(sock, forward_addr, local.addr(), dest, args.priority, packet)
                            sent_packets += 1
                            # Only display data packet for initial transmit
                            if attempt == 1:
                                packet.display(dest, True)
                            else:
                                dropped_packets += 1
                        # Store updated information
                        window[key] = (packet, attempt, now(), failed)

                    try:
                        # Try reading acknowledgement packet from socket
                        data, remote = sock.recvfrom(10240)
                        frame = Frame(data=data)
                        ack = frame.getPacket()

                        # Remove ack'ed data packet from window
                        if ack.type == P_ACK:
                            if ack.seq in window:
                                finished.append(ack.seq)
                    except BlockingIOError:
                        pass

                # Remove acknowledged packets from window and parse another
                for s in finished:
                    del window[s]
                    seq += 1
                    # Parse new packet to add to window
                    packet = create_packet(f, args.length, seq)
                    if packet is not None:
                        window[seq] = (packet, 0, 0, False)
                    else:
                        seq -= 1

                # Count number of failed packets in the window
                failed_packets = sum([int(info[3]) for info in window.values()])

                # If all packets in window have failed exit loop
                if len(window) > 0 and failed_packets == len(window):
                    print(f"Error: All {len(window)} packets in window have failed.")
                    break
    else:
        # Requested file not found locally
        print(f"Error: File '{request.payload}' requested from {requester[0]}:{requester[1]} not found!")

    # Create final END packet, encode, and send over network
    packet = send_frame(sock, forward_addr, local.addr(), dest, args.priority, Packet(type=P_END, sequence=seq))
    # Dsiplay END packet information
    packet.display(dest, True)

    # Display packet loss percentage
    packet_loss = dropped_packets / sent_packets
    print(f"\nPacket lost: {packet_loss:.2f}%")

    sock.close()

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="sender.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 2: Network Emulator and Reliable Transfer

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
        "-i",
        "--priority",
        metavar="<N>",
        dest="priority",
        action="store",
        type=int,
        default=3,
        choices=range(1,4),
        help="Packet priority [1,2,3]",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        metavar="<milliseconds>",
        dest="timeout",
        action="store",
        type=int,
        default=300000,
        help="Packet acknowledgement timeout (default 5 minutes)",
    )

    parser.add_argument(
        "-a",
        "--attempts",
        metavar="<N>",
        dest="attempts",
        action="store",
        type=int,
        default=5,
        help="Max number of attempts to send a packet",
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
    if args.rate <= 0:
        print(f"Error: Invalid packet rate ({args.rate}) sepcified. Must be a non-zero positive integer")
        invalid_args = True

    if args.length <= 0:
        print(f"Error: Invalid packet length ({args.length}) sepcified. Must be a non-zero positive integer")
        invalid_args = True

    if args.sequence_no < 0:
        print(f"Error: Invalid sequence number ({args.sequence_no}) sepcified. Must be a positive integer")
        invalid_args = True

    if args.timeout <= 0:
        print(f"Error: Invalid packet ack timeout ({args.timeout}). Must be non-zero positive integer.")
        invalid_args = True

    if args.attempts <= 0:
        print(f"Error: Invalid max send packet attempts ({args.attempts}). Must be non-zero positive integer.")
        invalid_args = True

    if not is_valid_port(args.my_port):
        print(f"Error: Invalid port specified ({args.my_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if not is_valid_port(args.requester_port):
        print(f"Error: Invalid requester port specified ({args.requester_port}). Out of range 2049 < p < 65536")
        invalid_args = True

    if not is_valid_port(args.forward_port):
        print(f"Error: Invalid emulator port specified ({args.forward_port}). Out of range 2049 < p < 65536")
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
