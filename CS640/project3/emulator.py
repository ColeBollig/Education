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

VERBOSITY = 0

#------------------------------------------------------------------
def log(msg: str, level: int = 0):
    if VERBOSITY >= level:
        print(msg)

#------------------------------------------------------------------
class Topology:
    """Class to hold this emulators view of the network topology"""
    def __init__(self, topology_file, local):
        self.table = dict() # Forwarding table {destination : next-hop}
        self.neighbors = dict() # Information regarding my neighbors {neighbor : (last-hello-time, alive, cost)}
        self.link_states = dict() # Stored view of all emulators and their link states {em : (seq,{neighbor:cost})}
        self.ext_neighbors = set() # Neighbors not specified in topology file (i.e. senders/requesters)
        self.seq = 0 # Current link state packet sequence (increments)
        self.addr = local # My Host information (ip:port)
        line_no = 0
        try:
            # Read forwarding topology file
            with open(topology_file, "r") as f:
                for line in f:
                    line_no += 1
                    # ignore empty lines are lines starting w/ #
                    line = line.strip()
                    if line == "" or line[0] == "#":
                        continue
                    # Split all information based on spaces
                    info, *neighbors = line.split(" ")
                    # Parse emulator information
                    ip, port = info.split(",")
                    emulator = Host(ip, port)
                    self.link_states[emulator] = (None, dict())

                    # Add all links to link state dictionary
                    t = now()
                    for info in neighbors:
                        ip, port, cost = info.split(",")
                        host = Host(ip, port)
                        cost = int(cost)
                        self.link_states[emulator][1].update({host : cost})
                        # If parsed info belongs to this emulator the update neighbors dictionary
                        if emulator == self.addr:
                            self.neighbors.update({host : (t, True, cost)})
        # Parse failure has occurred
        except Exception as e:
            raise RuntimeError(f"Error: Failed to parse topology file '{topology_file}' (@{line_no}): {e}")
        # Create initial routes and fowarding table
        self.create_routes()
    def create_routes(self):
        """Build forwarding table based on topology and Djikstra's shortest path algorithm"""
        self.table = dict()
        known_hosts = dict()
        # Add every single host to known_hosts
        for emulator, info in self.link_states.items():
            known_hosts[emulator] = None
            for host in info[1].keys():
                known_hosts[host] = None
        # Set known hosts root host to this host
        known_hosts[self.addr] = (0, None)
        # While any known hosts have no associated path calculate shortest paths from root
        while None in known_hosts.values():
            costs = list()
            # Loop through all known hosts
            for known, info in known_hosts.items():
                # If we have found a path and it exists in the link states table
                if info is not None and known in self.link_states:
                    # Get stored path neighbor hop and total cost
                    stored_cost, hop = info
                    # Loop through this host link states
                    for host, cost in self.link_states[known][1].items():
                        # Add potential path (cost, neighbor hop) if the link state host doesn't have a path already
                        if known_hosts[host] is None and cost is not None:
                            # Calculate path cost and get which hop this is from
                            calc_cost = cost + stored_cost
                            neighbor = host if hop is None else hop
                            # Add info to list of path costs
                            costs.append((calc_cost, host, neighbor))

            # If we have no more costs to contribute then break out of loop
            if len(costs) == 0:
                break

            # Get the cheapest cost path and update information (forwarding table and known host paths)
            cost, dest, hop = sorted(costs, key=lambda x: x[0])[0]
            known_hosts[dest] = (cost, hop)
            self.table[dest] = hop
        # Print topology and forwarding table
        self._print_topology()
        self._print_table()
    def update_link_states(self, host: Host, update_info: str, seq: int) -> int:
        """Update internal stored link states with incoming information from neighbor"""
        action = LSP_DO_NOTHING
        update = False
        if host not in self.link_states:
            # Incoming host is not already in link states table so add default entry
            action = LSP_FORWARD
            self.link_states[host] = (seq, dict())
            update = True
        else:
            # Incoming host exists in link state so check incoming sequence number
            curr_seq = self.link_states[host][0]
            if curr_seq is None or curr_seq < seq:
                # Current stored sequence number is less than incoming one so update link states
                action = LSP_FORWARD
                self.link_states[host] = (seq, self.link_states[host][1])
                update = True
            elif curr_seq > seq:
                # Current stored sequence number is higher so update sedning host
                action = LSP_UPDATE_SENDER
        # If we need to update our link states -> do so
        if update:
            stored = self.link_states[host][0]
            self.link_states[host] = (stored, dict())
            # Update this hosts link state information
            for info in update_info.split(" "):
                ip, port, cost = info.split(",")
                neighbor = Host(ip, port)
                cost = int(cost)
                self.link_states[host][1].update({neighbor : cost})
            # Create new routes
            self.create_routes()
        return action
    def _new_sequence(self):
        """Get the newest sequence number for link state packets"""
        self.seq += 1
        return self.seq
    def makeLinksPacket(self, emulator: tuple = None) -> Packet:
        """Make link state packet for flooding to network for an emulator (None = this emulator)"""
        # Check if we have to get link state info for a specific emulator or ourselves
        if emulator is None:
            emulator = self.addr.addr()
            seq = self._new_sequence()
        else:
            seq = self.link_states[emulator][0]
        info = list()
        # Create string information (ip,port,cost) for all of emulators links
        for host, cost in self.link_states[emulator][1].items():
            # If cost is none (due to direct neighbor being down) ignore
            if cost is not None:
                info.append(f"{host.ip()},{host.port},{cost}")
        # Create link state encoding and packet
        state = LinkState(ip=emulator[0], port=emulator[1], sequence=seq, ttl=30, links=" ".join(info))
        return Packet(type=P_LINK, payload=state.encode())
    def get(self, key: tuple) -> Host:
        """Get next hop from forwarding table based on destination key"""
        return self.table.get(key)
    def getNeighbors(self) -> dict:
        """Return list of direct neighbors"""
        return self.neighbors
    def checkNeighbors(self, timeout: int) -> bool:
        """Check if direct neighbors are alive"""
        update = False
        remove = [] # External neighbors to remove due to no keep alive
        # Check aliveness for each neighbor
        for host, info in self.neighbors.items():
            heartbeat, alive, cost = info
            if alive and now() - heartbeat > timeout:
                # Was alive but heartbeat (hello) not sent within specified timeout
                log(f"Neighbor {host.str()} offline")
                if host.addr() in self.ext_neighbors:
                    # External neighbor (requester/sender) update info and remove from neighbors
                    self.ext_neighbors.remove(host.addr())
                    remove.append(host.addr())
                    del self.link_states[self.addr][1][host]
                else:
                    # Neighbor from topology file so update information
                    self.neighbors[host] = (heartbeat, False, cost)
                    self.link_states[self.addr][1][host] = None
                update = True
        # Remove dead external neighbors
        for addr in remove:
            del self.neighbors[addr]
        # We updated our information so create new routes
        if update:
            self.create_routes()
        return update
    def receivedHello(self, addr: tuple) -> bool:
        """Handle reveiving a hello message from a neighbor"""
        update = False
        if addr not in self.neighbors:
            # Recieved hello from external neighbor (sender/requester) update information
            incoming = Host(addr[0], addr[1])
            self.neighbors[incoming] = (now() + (30 * 60 * 1000), True, 1)
            self.link_states[self.addr][1][incoming] = 1
            self.ext_neighbors.add(incoming)
            update = True
        else:
            # Received hello from neighbor
            alive, orig_cost = self.neighbors[addr][1:]
            self.neighbors[addr] = (now(), True, orig_cost)
            self.link_states[self.addr][1][addr] = orig_cost
            update = (alive == False)
        # We added or revived a neighbor to create routes
        if update:
            self.create_routes()
        return update
    def _print_topology(self):
        """Print the stored topology"""
        title = "__TOPOLOGY__"
        print(f"\n{title:^45}")
        for emulator, info in self.link_states.items():
            if emulator in self.neighbors and not self.neighbors[emulator][1]:
                continue
            links = []
            for host, cost in info[1].items():
                if cost is not None:
                    links.append(f"{host.str()},{cost}")
            disp = " ".join(links)
            print(f"{emulator.str()} {disp}")
    def _print_table(self):
        """Print the current forwarding table"""
        title = "_FORWARDING TABLE_"
        print(f"\n{title:^45}")
        div = "+---------------------+---------------------+"
        print(div)
        print("|   Destination Host  |    Next Hop Host    |")
        print("+=====================+=====================+")
        for dest, next_hop in self.table.items():
            print(f"|{dest.str():^21}|{next_hop.str():^21}|")
            print(div)

#------------------------------------------------------------------
def forward(sock, topology, frame):
    """General forward a frame to the next hop (for data, request, end, ack, & trace packets)"""
    next_hop = topology.get(frame.getDestAddr())
    if next_hop is None:
        log(f"Failed to find next hop for frame: {frame}")
    else:
        log(f"Forwarding frame----: {frame}", 1)
        sock.sendto(frame.encode(), next_hop.addr())

#------------------------------------------------------------------
def emulate(args):
    """Emulate forwarding table devices (switches) to enable packet forwarding"""

    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.socket_timeout)
    sock.bind(('', args.my_port))
    sock.setblocking(False)

    local = get_local_host(args.my_port)
    topology = Topology(args.topology_file, local)
    last_link_state_t = last_hello_t = 0

    # Forever loop
    while True:
        frame = None
        try:
            # Recieve Frame
            data, requester = sock.recvfrom(10240)
            frame = Frame(data=data)
        except BlockingIOError:
            pass

        # Determine if we should by default send our link states to network
        update_state = (now() - last_link_state_t > args.periodic_link_update)

        # If we received a frame
        if frame is not None:
            # Decode packet
            packet = frame.getPacket()
            # Handle hello message
            if packet.is_hello():
                log(f"Recieved Hello------: {frame}", 3)
                if topology.receivedHello(frame.getSrcAddr()):
                    update_state = True
            # Handle trace route packet
            elif packet.is_trace_route():
                log(f"Recieved Trace Route: {frame}", 1)
                ttl = packet.seq
                # Check if trace packet is expired
                if ttl == 0:
                    # Send direct response to packet origin
                    src = frame.getSrcAddr()
                    log("Trace packet TTL expired...", 1)
                    send_frame(sock, src, local.addr(), src, packet)
                else:
                    # Not expired... decrease ttl and forward
                    ttl -= 1
                    packet.seq = ttl
                    next_hop = topology.get(frame.getDestAddr())
                    frame.payload = packet.encode()
                    forward(sock, topology, frame)
            # Handle link state packet
            elif packet.is_link_state():
                log(f"Recieved Link State-: {frame}", 2)
                # Decode link state information
                state = LinkState(data=packet.payload)
                # Update our information
                action = topology.update_link_states(state.host(), state.links, state.seq)
                sender = frame.getSrcAddr()
                # Check if the state is not expired and should be forwarded -> forward
                if action == LSP_FORWARD and not state.expired():
                    state.decay() # Decrease TTL
                    p = Packet(type=P_LINK, payload=state.encode())
                    # Send link states to all neighbors excluding sender
                    for host in topology.getNeighbors().keys():
                        if host != sender:
                            log(f"Forwarding Link State", 2)
                            send_frame(sock, host.addr(), local.addr(), host.addr(), p)
                # We have more up to dat info to pass data to sender
                elif action == LSP_UPDATE_SENDER:
                    links = topology.makeLinksPacket(sender)
                    log("Sending updated link state back to neighbor", 1)
                    send_frame(sock, sender, local.addr(), sender, links)
            # Handle all other packets (i.e. forward)
            else:
                log(f"Recieved frame------: {frame}", 1)
                forward(sock, topology, frame)

        # Check for neighbors that have disappeared (i.e. no hello in specified time)
        if topology.checkNeighbors(args.neighbor_offline_timeout):
            update_state = True

        hello = Packet(type=P_HELLO)
        links = topology.makeLinksPacket()
        sent_hello = False
        curr_t = now()

        # Send updates to alive nieghbors that we have table entries for
        for host, info in topology.getNeighbors().items():
            alive = info[1]
            if not alive:
                continue
            next_hop = topology.get(host.addr())
            if next_hop is None:
                continue
            if curr_t - last_hello_t > args.hello_interval:
                sent_hello = True
                log(f"Sending Hello to {host.str()}", 4)
                send_frame(sock, next_hop.addr(), local.addr(), host.addr(), hello)
            if update_state:
                log(f"Sending link states to {host.str()}", 4)
                send_frame(sock, next_hop.addr(), local.addr(), host.addr(), links)

        # Store last update times (link state and hello)
        if sent_hello:
            last_hello_t = curr_t
        if update_state:
            last_link_state_t = now()

#------------------------------------------------------------------
def parse_args():
    """Function to handle all CLI argument parsing"""

    parser = argparse.ArgumentParser(
        prog="emulator.py",
        description=textwrap.dedent(
            f"""
            UW-Madison CS640 Fall 2024
            Project 3: Link State Protocol and Trace Route

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
        "-f",
        "--topoplogy-file",
        metavar="<filename>",
        dest="topology_file",
        action="store",
        type=str,
        default="topology.txt",
        help="File containing network topology information.",
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
        "-o",
        "--offline-timeout",
        metavar="<millisecond>",
        dest="neighbor_offline_timeout",
        action="store",
        type=int,
        default=2500,
        help="Timeout in milliseconds to wait for a Hello Message before marking a neighbor as offline",
    )

    parser.add_argument(
        "-n",
        "--notify-neighbor",
        metavar="<millisecond>",
        dest="hello_interval",
        action="store",
        type=int,
        default=500,
        help="Time interval in milliseconds for sending keep alive hello's to neighbors",
    )

    parser.add_argument(
        "-u",
        "--update-link-state",
        metavar="<millisecond>",
        dest="periodic_link_update",
        action="store",
        type=int,
        default=60000,
        help="Time interval in milliseconds to send periodic link state updates",
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

    if invalid_args:
        sys.exit(1)

#------------------------------------------------------------------
def main():
    global VERBOSITY

    args = parse_args()
    check_args(args)

    # Set print verbosity
    VERBOSITY = args.verbosity

    # Emulate packet forwarding
    emulate(args)

if __name__ == "__main__":
    main()