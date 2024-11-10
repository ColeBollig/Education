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
def delay(rate: int, start: int = None):
    start = now() if start is None else start
    delay = (1000 / rate)
    while now() - start < delay:
        pass
    return now()

#------------------------------------------------------------------
def is_valid_port(port: int):
    return port > 2049 and port < 65536

#------------------------------------------------------------------
# Class that represents a host provided a hostname and port
class Host:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.host = socket.gethostbyname(hostname)
        self.port = int(port)
        if not is_valid_port(self.port):
            raise RuntimeError(f"Invalid port number ({self.port}). Out of range 2049 < p < 65536")
    # Make class hashable for acting as key in dictionary
    def __hash__(self):
        return hash(self.addr())
    # Allow comaprison to other Host or tuple of (ipv4, port)
    def __eq__(self, other):
        return self.addr() == other.addr() if isinstance(other, Host) else (self.addr() == other if isinstance(other, tuple) else False)
    # Allow conversion to string for debugging
    def __str__(self) -> str:
        return f"{self.hostname}({self.host}:{self.port})"
    # Return a socket address tuple (IP, Port)
    def addr(self) -> tuple:
        return (self.host, self.port)
    def str(self):
        return f"{self.host}:{self.port}"

#------------------------------------------------------------------
def get_local_host(port: int) -> Host:
    return Host(socket.gethostname(), port)

#------------------------------------------------------------------
P_REQUEST = b'R'
P_DATA = b'D'
P_END = b'E'
P_ACK = b'A'
P_UNDEF = b'-'

#------------------------------------------------------------------
PACKET_TYPE = {
    P_REQUEST : "REQUEST",
    P_DATA : "DATA",
    P_END : "END",
    P_ACK : "ACKNOWLEDGEMENT",
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
    def is_end(self):
        return self.type == P_END
    # Check if packet represents a DATA packet
    def is_data(self):
        return self.type == P_DATA
    def is_droppable(self):
        return self.type != P_REQUEST and self.type != P_END
    # Encode the Packet to transmit over network
    def encode(self):
        self.send_t = timestamp()
        header = struct.pack(
            "!cII",
            self.type,
            socket.htonl(self.seq),
            socket.htonl(self.len)
        )
        return header + self.payload.encode()
    # Decode a transmitted network packet
    def decode(self, data):
        self.recieve_t = timestamp()
        header = data[:9]
        self.payload = data[9:].decode()
        header = struct.unpack("!cII", header)
        self.type = header[0]
        self.seq = socket.ntohl(header[1])
        self.len = socket.ntohl(header[2])
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
    def __str__(self):
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
PRIO_HIGH = 0x01
PRIO_MEDIUM = 0x02
PRIO_LOW = 0x03

#------------------------------------------------------------------
class Frame:
    def __init__(self, **kwargs):
        data = kwargs.get("data")
        if data is not None:
            self.decode(data)
        else:
            self.priority = kwargs.get("priority", PRIO_HIGH)
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
            "!B4sH4sHI",
            self.priority,
            socket.inet_aton(self.src_ip),
            socket.htons(self.src_port),
            socket.inet_aton(self.dest_ip),
            socket.htons(self.dest_port),
            socket.htonl(self.len)
        )
        return header + self.payload
    def decode(self, data):
        header = data[:17]
        self.payload = data[17:]
        header = struct.unpack("!B4sH4sHI", header)
        self.priority = header[0]
        self.src_ip = socket.inet_ntoa(header[1])
        self.src_port = socket.ntohs(header[2])
        self.dest_ip = socket.inet_ntoa(header[3])
        self.dest_port = socket.ntohs(header[4])
        self.len = socket.ntohl(header[5])
    def getPacket(self) -> Packet:
        return Packet(data=self.payload)
    def getSrcAddr(self) -> tuple:
        return (self.src_ip, self.src_port)
    def getDestAddr(self) -> tuple:
        return (self.dest_ip, self.dest_port)
    def prio_str(self) -> str:
        if self.priority == PRIO_HIGH:
            return f"high priority (0x{PRIO_HIGH:x})"
        elif self.priority == PRIO_MEDIUM:
            return f"medium priority (0x{PRIO_MEDIUM:x})"
        elif self.priority == PRIO_LOW:
            return f"low priority (0x{PRIO_LOW:x})"
        raise RuntimeError(f"Unknown frame priority: 0x{self.priority:x}")
    def __str__(self):
        payload = str(self.payload).replace("\n", "\\n")
        source = f"{self.src_ip}:{self.src_port}"
        destination = f"{self.dest_ip}:{self.dest_port}"
        return f"[0x{self.priority:x}|{source}|{destination}|{self.len}/{len(self.payload)}|'{payload}']"

#------------------------------------------------------------------
def send_frame(sock: socket.socket, addr: tuple, src: tuple, dest:tuple, prio: int, packet: Packet):
    frame = Frame(priority=prio, source=src, destination=dest, payload=packet.encode())
    sock.sendto(frame.encode(), addr)
    return packet
