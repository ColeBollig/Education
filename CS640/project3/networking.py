import socket
import struct
import enum
from time import time
from datetime import datetime

__author__ = "Cole Bollig"
__email__ = "cabollig@wisc.edu"

#------------------------------------------------------------------
def timestamp() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:22]

#------------------------------------------------------------------
def now() -> int:
    """Get timestamp in milliseconds"""
    return time() * 1000

#------------------------------------------------------------------
def delay(rate: int, start: int = None) -> int:
    start = now() if start is None else start
    delay = (1000 / rate)
    while now() - start < delay:
        pass
    return now()

#------------------------------------------------------------------
def is_valid_port(port: int) -> bool:
    return port > 2049 and port < 65536

#------------------------------------------------------------------
# Class that represents a host provided a hostname and port
class Host:
    def __init__(self, identifier, port):
        try:
            socket.inet_aton(identifier)
            self.hostname = "no-hostname"
            self.host = identifier
        except socket.error:
            self.hostname = identifier
            self.host = socket.gethostbyname(identifier)
        self.port = int(port)
        if not is_valid_port(self.port):
            raise RuntimeError(f"Invalid port number ({self.port}). Out of range 2049 < p < 65536")
    # Make class hashable for acting as key in dictionary
    def __hash__(self) -> hash:
        return hash(self.addr())
    # Allow comaprison to other Host or tuple of (ipv4, port)
    def __eq__(self, other) -> bool:
        return self.addr() == other.addr() if isinstance(other, Host) else (self.addr() == other if isinstance(other, tuple) else False)
    # Allow conversion to string for debugging
    def __str__(self) -> str:
        return f"{self.hostname}({self.host}:{self.port})"
    # Return a socket address tuple (IP, Port)
    def addr(self) -> tuple:
        return (self.host, self.port)
    def ip(self) -> str:
        return self.host
    def str(self) -> str:
        return f"{self.host}:{self.port}"

#------------------------------------------------------------------
def get_local_host(port: int) -> Host:
    return Host(socket.gethostname(), port)

#------------------------------------------------------------------
LSP_DO_NOTHING = 0
LSP_FORWARD = 1
LSP_UPDATE_SENDER = 2

#------------------------------------------------------------------
class LinkState():
    def __init__(self, **kwargs):
        data = kwargs.get("data")
        if data is not None:
            self.decode(data)
        else:
            self.orig_ip = kwargs["ip"]
            self.orig_port = kwargs["port"]
            self.seq = kwargs.get("sequence", 0)
            self.ttl = kwargs["ttl"]
            self.links = kwargs["links"]
    def encode(self):
        header = struct.pack(
            "!4sHII",
            socket.inet_aton(self.orig_ip),
            socket.htons(self.orig_port),
            socket.htonl(self.seq),
            socket.htonl(self.ttl),
        )
        return header + self.links.encode()
    def decode(self, data):
        header = data[:14]
        self.links = data[14:].decode()
        header = struct.unpack("!4sHII", header)
        self.orig_ip = socket.inet_ntoa(header[0])
        self.orig_port = socket.ntohs(header[1])
        self.seq = socket.ntohl(header[2])
        self.ttl = socket.ntohl(header[3])
    def expired(self) -> bool:
        return self.ttl == 0
    def decay(self):
        if self.ttl > 0:
            self.ttl -= 1
    def host(self) -> Host:
        return Host(self.orig_ip, self.orig_port)
    def __str__(self):
        return f"[{self.orig_ip}:{self.orig_port}|{self.seq}|{self.ttl}|'{self.links}']"

#------------------------------------------------------------------
P_REQUEST = b'R'
P_DATA = b'D'
P_END = b'E'
P_ACK = b'A'
P_HELLO = b'H'
P_LINK = b'L'
P_TRACE = b'T'
P_UNDEF = b'-'

#------------------------------------------------------------------
PACKET_TYPE = {
    P_REQUEST : "REQUEST",
    P_DATA : "DATA",
    P_END : "END",
    P_ACK : "ACKNOWLEDGEMENT",
    P_HELLO : "HELLO",
    P_LINK : "LINK-STATE",
    P_TRACE : "TRACE-ROUTE",
    P_UNDEF : "UNDEFINED",
}

#------------------------------------------------------------------
# Class representing a Packet (Lowest level data encapsulation)
class Packet:
    def __init__(self, **kwargs):
        data = kwargs.get("data")
        if data is not None:
            self.decode(data)
        else:
            self.type = kwargs.get("type", P_UNDEF)
            self.payload = kwargs.get("payload", "")
            self.seq = kwargs.get("sequence", 0)
            self.len = kwargs.get("length", len(self.payload))
        self.send_t = None
        self.recieve_t = None
        self.create_t = timestamp()
    # Check if a packet represents an END packet
    def is_end(self) -> bool:
        return self.type == P_END
    # Check if packet represents a DATA packet
    def is_data(self) -> bool:
        return self.type == P_DATA
    # Check if packet represents a HELLO packet
    def is_hello(self) -> bool:
        return self.type == P_HELLO
    # Check if packet represents a TRACE (Route) packet
    def is_trace_route(self) -> bool:
        return self.type == P_TRACE
    # Check if packet represents a LINK (State) packet
    def is_link_state(self) -> bool:
        return self.type == P_LINK
    def is_droppable(self) -> bool:
        return self.type != P_REQUEST and self.type != P_END
    def _encode_payload(self):
        return self.type not in [P_LINK]
    # Encode the Packet to transmit over network
    def encode(self):
        self.send_t = timestamp()
        header = struct.pack(
            "!cII",
            self.type,
            socket.htonl(self.seq),
            socket.htonl(self.len)
        )
        return header + (self.payload.encode() if self._encode_payload() else self.payload)
    # Decode a transmitted network packet
    def decode(self, data):
        self.recieve_t = timestamp()
        header = data[:9]
        header = struct.unpack("!cII", header)
        self.type = header[0]
        self.seq = socket.ntohl(header[1])
        self.len = socket.ntohl(header[2])
        self.payload = (data[9:].decode() if self._encode_payload() else data[9:])
    def display(self, host: tuple = ("???.???.???.???", "????"), sender: bool = False):
        time = f"Creation Time---: {self.create_t}"
        if self.recieve_t is not None:
            time = f"Recieve Time----: {self.recieve_t}"
        elif self.send_t is not None:
            time = f"Send Time-------: {self.send_t}"
        from_prog = "Request Address-:" if sender else "Sender Address--:"
        four_bytes = self.payload[:4].replace("\n", "\\n")
        print(
f"""{self.type_str()} Packet
    {time}
    {from_prog} {host[0]}:{host[1]}
    Sequence Number-: {self.seq}
    Length----------: {self.len}
    Payload (4B)----: '{four_bytes}'
""")
    # Allow conversion into a string type for debugging
    def __str__(self) -> str:
        payload = self.payload.replace("\n", "\\n")
        return f"[{self.type}|{self.seq}|{self.len}/{len(self.payload)}|'{payload}']"
    # Return full Packet type name from single character representation
    def type_str(self) -> str:
        return PACKET_TYPE.get(self.type, "UNKNOWN")

#------------------------------------------------------------------
def packet_type(payload: str) -> str:
    try:
        p = Packet(data=payload)
        return p.type_str()
    except Exception as e:
        return "UNKNOWN"

#------------------------------------------------------------------
class Frame:
    def __init__(self, **kwargs):
        data = kwargs.get("data")
        if data is not None:
            self.decode(data)
        else:
            src = kwargs.get("source")
            if src is not None:
                self.src_ip = src[0]
                self.src_port = src[1]
            else:
                self.src_ip = kwargs["src_ip"]
                self.src_port = kwargs["src_port"]
            dest = kwargs.get("destination")
            if dest is not None:
                self.dest_ip = dest[0]
                self.dest_port = dest[1]
            else:
                self.dest_ip = kwargs["dest_ip"]
                self.dest_port = kwargs["dest_port"]
            self.payload = kwargs.get("payload", "")
            self.len = len(self.payload)
    def encode(self):
        header = struct.pack(
            "!4sH4sHI",
            socket.inet_aton(self.src_ip),
            socket.htons(self.src_port),
            socket.inet_aton(self.dest_ip),
            socket.htons(self.dest_port),
            socket.htonl(self.len),
        )
        return header + self.payload
    def decode(self, data):
        header = data[:16]
        self.payload = data[16:]
        header = struct.unpack("!4sH4sHI", header)
        self.src_ip = socket.inet_ntoa(header[0])
        self.src_port = socket.ntohs(header[1])
        self.dest_ip = socket.inet_ntoa(header[2])
        self.dest_port = socket.ntohs(header[3])
        self.len = socket.ntohl(header[4])
    def getPacket(self) -> Packet:
        return Packet(data=self.payload)
    def getSrcAddr(self) -> tuple:
        return (self.src_ip, self.src_port)
    def getDestAddr(self) -> tuple:
        return (self.dest_ip, self.dest_port)
    def __str__(self) -> str:
        payload = str(self.payload).replace("\n", "\\n")
        source = f"{self.src_ip}:{self.src_port}"
        destination = f"{self.dest_ip}:{self.dest_port}"
        return f"[{source}|{destination}|{self.len}/{len(self.payload)}|'{payload}']"

#------------------------------------------------------------------
def send_frame(sock: socket.socket, addr: tuple, src: tuple, dest:tuple, packet: Packet) -> Packet:
    frame = Frame(source=src, destination=dest, payload=packet.encode())
    sock.sendto(frame.encode(), addr)
    return packet
