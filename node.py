import socket
import threading
import struct
import time
import json
import builtins
from DataPacket import DataPacket
from RouteDataPacket import RouteDataPacket
from InterestPacket import InterestPacket
from datetime import datetime
from collections import deque

_print_lock = threading.Lock()
_original_print = builtins.print
def _thread_safe_print(*args, **kwargs):
    # always flush so ordering is visible immediately
    kwargs.setdefault("flush", True)
    with _print_lock:
        _original_print(*args, **kwargs)
# Replace built-in print for this process so all prints are serialized
builtins.print = _thread_safe_print

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6
ROUTE_ACK = 0x7

# Flag Masks (lower 4 bits)
ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

# Error codes
FORMAT_ERROR = 0x1
NAME_ERROR = 0x2
NO_DATA_ERROR = 0X3
DROPPED_ERROR = 0X4

FRAGMENT_SIZE = 1500

def create_interest_packet(seq_num, name, flags=0x0, origin_node="", data_flag=False, visited_domains=None):
    if visited_domains is None:
        visited_domains = []

    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes)

    data_flag_byte = b'\x01' if data_flag else b'\x00'

    # ---- Encode visited_domains ----
    vd_count = len(visited_domains) & 0xFF
    vd_bytes = bytes([vd_count])

    for dom in visited_domains:
        dom_b = dom.encode("utf-8")
        vd_bytes += bytes([len(dom_b) & 0xFF]) + dom_b

    # ---- Build packet ----
    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = (
        header +
        name_bytes +
        bytes([origin_length]) +
        origin_bytes +
        data_flag_byte +
        vd_bytes
    )

    return packet

def create_data_packet(seq_num, name, payload, flags=0x0, fragment_num=1, total_fragments=1):
    packet_type = DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBBBB", packet_type_flags, seq_num, payload_size, name_length, fragment_num, total_fragments)
    packet = header + name_bytes + payload_bytes
    return packet

def create_error_packet(seq_num, name, error_code, origin_node="", flags=0x0):
    """
    Build an ERROR packet with origin node info:
    Header: packet_type&flags (1 byte), seq_num (1 byte),
            error_code (1 byte), name_length (1 byte)
    Then: name (variable), origin_length (1 byte), origin_node (variable)
    """
    packet_type = ERROR
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    err_code = error_code & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF
    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, err_code, name_length)
    packet = header + name_bytes + struct.pack("!B", origin_length) + origin_bytes
    return packet

def parse_error_packet(packet):
    if len(packet) < 5:
        raise ValueError("Invalid ERROR packet: too short")

    packet_type_flags, seq_num, err_code, name_length = struct.unpack("!BBBB", packet[:4])
    name_start = 4
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")

    if len(packet) > name_end:
        origin_length = packet[name_end]
        origin_start = name_end + 1
        origin_end = origin_start + origin_length
        origin_node = packet[origin_start:origin_end].decode("utf-8")
    else:
        origin_node = ""

    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "ErrorCode": err_code,
        "Name": name,
        "OriginNode": origin_node
    }

def parse_interest_packet(packet):
    packet_type_flags, seq_num, name_length = struct.unpack("!BBB", packet[:3])

    name_start = 3
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")

    origin_length = packet[name_end]
    origin_start = name_end + 1
    origin_end = origin_start + origin_length
    origin_node = packet[origin_start:origin_end].decode("utf-8")

    data_flag = bool(packet[origin_end])  # 1 byte after origin

    # ---- Parse visited domains ----
    vd_index = origin_end + 1
    visited_count = packet[vd_index]
    vd_index += 1

    visited_domains = []
    for _ in range(visited_count):
        dom_len = packet[vd_index]
        vd_index += 1
        dom = packet[vd_index:vd_index + dom_len].decode("utf-8")
        vd_index += dom_len
        visited_domains.append(dom)

    # Extract fields
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "OriginNode": origin_node,
        "DataFlag": data_flag,
        "VisitedDomains": visited_domains,
    }

def parse_route_data_packet(packet):
    """
    Canonical parser for ROUTING_DATA packets.
    Header: !BBBB => packet_type_flags, seq_num, info_size, name_length
    Payload: name_bytes (name_length), then routing_info_bytes (info_size)
    routing_info is JSON when sent by NameServer.
    """
    if len(packet) < 4:
        raise ValueError("Packet too short for ROUTE header")
    packet_type_flags, seq_num, info_size, name_length = struct.unpack("!BBBB", packet[:4])
    total_len = 4 + name_length + info_size
    if len(packet) < total_len:
        raise ValueError("Packet shorter than declared ROUTE lengths")

    name = packet[4:4 + name_length].decode("utf-8", errors="ignore")
    info_bytes = packet[4 + name_length:4 + name_length + info_size]
    try:
        info_text = info_bytes.decode("utf-8", errors="ignore")
    except Exception:
        info_text = ""

    info_json = None
    try:
        info_json = json.loads(info_text) if info_text else None
    except Exception:
        info_json = None

    # Normalize fields from JSON payload (if present)
    origin_name = None
    path = []
    dest = None
    next_hop = None
    next_hop_port = None
    path_to_origin = None

    if isinstance(info_json, dict):
        origin_name = info_json.get("origin_name") or info_json.get("origin")
        path = info_json.get("path") or []
        dest = info_json.get("dest")
        next_hop = info_json.get("next_hop")
        next_hop_port = info_json.get("next_hop_port")
        path_to_origin = info_json.get("path_to_origin")
    elif isinstance(info_text, str) and "," in info_text:
        path = [p.strip() for p in info_text.split(",") if p.strip()]

    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF
    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "InfoSize": info_size,
        "NameLength": name_length,
        "Name": name,
        "OriginName": origin_name,
        "Path": path,
        "Dest": dest,
        "NextHop": next_hop,
        "NextHopPort": next_hop_port,
        "PathToOrigin": path_to_origin,
        "RoutingInfo": info_text,
        "RoutingInfoJson": info_json,
    }

def parse_data_packet(packet):
    packet_type_flags, seq_num, payload_size, name_length, fragment_num, total_fragments = struct.unpack("!BBBBBB", packet[:6])
    name_start = 6
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")
    payload = packet[name_end:name_end + payload_size]
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "PayloadSize": payload_size,
        "NameLength": name_length,
        "Name": name,
        "Payload": payload.decode("utf-8", errors="ignore"),
        "FragmentNum": fragment_num,
        "TotalFragments": total_fragments,
    }

def create_route_data_packet(seq_num, name, routing_info, flags=0x0):
    """
    Helper to create ROUTING_DATA packets. routing_info typically a dict.
    """
    packet_type = ROUTING_DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    if isinstance(routing_info, dict):
        payload_json = json.dumps(routing_info)
        payload_bytes = payload_json.encode("utf-8")
    else:
        payload_bytes = routing_info.encode("utf-8") if isinstance(routing_info, str) else routing_info
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, payload_size, name_length)
    return header + name_bytes + payload_bytes

# ---------------- HELLO / UPDATE Packets ----------------
def create_hello_packet(name):
    packet_type = HELLO
    flags = ACK_FLAG
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BB", packet_type_flags, name_length)
    packet = header + name_bytes
    return packet

def create_hello_ns_packet(name):
    packet_type = HELLO
    flags = 0x0
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BB", packet_type_flags, name_length)
    packet = header + name_bytes
    return packet

def parse_hello_packet(packet):
    packet_type_flags, name_length = struct.unpack("!BB", packet[:2])
    name = packet[2:2 + name_length].decode("utf-8")

    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "NameLength": name_length,
        "Name": name
    }

def create_update_packet(name, origin_name, next_hop_port, number_of_hops):
    packet_type = UPDATE
    flags = 0x0
    packet_type_flags = (packet_type << 4) | flags

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    update_info = f"{name} {origin_name} {next_hop_port} {number_of_hops}"
    update_info_bytes = update_info.encode("utf-8")
    update_info_length = len(update_info_bytes)

    # Build packet header
    header = struct.pack("!BBH", packet_type_flags, name_length, update_info_length)
    return header + name_bytes + update_info_bytes

def parse_route_ack_packet(packet):
    """Parse ROUTE_ACK packets sent by nodes confirming a border path."""
    if len(packet) < 4:
        return None

    packet_type_flags, seq_num, info_size, name_length = struct.unpack("!BBBB", packet[:4])
    name_start = 4
    name_end = name_start + name_length
    if len(packet) < name_end:
        return None
    name = packet[name_start:name_end].decode("utf-8")

    idx = name_end
    # source_name_length
    if len(packet) < idx + 1:
        return None
    source_name_length = packet[idx]
    idx += 1
    if len(packet) < idx + source_name_length:
        return None
    source_name = packet[idx:idx + source_name_length].decode("utf-8")
    idx += source_name_length

    # hop_count
    if len(packet) < idx + 1:
        return None
    hop_count = packet[idx]
    idx += 1

    # visited domains
    visited_domains = []
    if len(packet) >= idx + 1:
        vd_count = packet[idx]
        idx += 1
        for _ in range(vd_count):
            if len(packet) < idx + 1:
                break
            dom_len = packet[idx]
            idx += 1
            if len(packet) < idx + dom_len:
                break
            dom = packet[idx:idx + dom_len].decode("utf-8")
            idx += dom_len
            visited_domains.append(dom)

    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "SourceName": source_name,
        "HopCount": hop_count,
        "VisitedDomains": visited_domains,
    }

def create_route_ack_packet(seq_num, name, flags=0x0, source_name="", hop_count=0, visited_domains=[]):
    """
    Create a ROUTE_ACK packet.

    Format:
      | packet_type_flags (1B) | seq_num (1B) | info_size (1B) | name_length (1B) |
      | name (variable) | source_name_length (1B) | source_name (variable) | hop_count (1B) |

    - packet_type_flags = (ROUTE_ACK << 4) | (flags & 0xF)
    - hop_count is 1 byte (0–255)
    """
    packet_type = ROUTE_ACK
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF

    source_name_bytes = source_name.encode("utf-8")
    source_name_length = len(source_name_bytes) & 0xFF

    # Build visited domains bytes: count (1B) followed by repeated (len(1B)+bytes)
    vd_bytes = b""
    for dom in visited_domains:
        dom_b = dom.encode("utf-8")
        vd_bytes += struct.pack("!B", len(dom_b) & 0xFF) + dom_b
    vd_count = len(visited_domains) & 0xFF

    # info_size counts: source_name_length + hop_count(1) + vd_count(1) + sum(each dom_len+1)
    info_size = source_name_length + 1 + 1 + sum((len(d.encode("utf-8")) & 0xFF) + 1 for d in visited_domains)

    header = struct.pack("!BBBB", packet_type_flags, seq_num, info_size, name_length)
    packet = (
        header
        + name_bytes
        + struct.pack("!B", source_name_length)
        + source_name_bytes
        + struct.pack("!B", hop_count)
        + struct.pack("!B", vd_count)
        + vd_bytes
    )
    return packet

def create_ns_update_packet(name, origin_name, next_hop_port, number_of_hops):
    packet_type = UPDATE
    flags = 0x1
    packet_type_flags = (packet_type << 4) | flags
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)
    update_info = f"{name} {origin_name} {next_hop_port} {number_of_hops}"
    update_info_bytes = update_info.encode("utf-8")
    update_info_length = len(update_info_bytes)
    header = struct.pack("!BBH", packet_type_flags, name_length, update_info_length)
    return header + name_bytes + update_info_bytes

def create_neighbor_update_packet(node_name, neighbor_name):
    """
    Creates an UPDATE packet (flag 0x2) for notifying a NameServer of neighbor relationships.
    Supports nodes and neighbors with multiple names (space-separated).
    
    Format:
      Header: !BBH (packet_type_flags, node_name_length, info_length)
      Payload: "<node_name> <neighbor_name>"
    
    Example:
      node_name="/DLSU/Router1 /ADMU/Router1"
      neighbor_name="/DLSU/Andrew /DLSU/Gokongwei"
    """
    packet_type = UPDATE
    flags = 0x2  # indicates neighbor update to NS
    packet_type_flags = (packet_type << 4) | flags

    # Normalize names (strip extra spaces)
    node_name = " ".join(node_name.strip().split())
    neighbor_name = " ".join(neighbor_name.strip().split())

    # Encode node name
    node_name_bytes = node_name.encode("utf-8")
    node_name_length = len(node_name_bytes)

    # Build payload (update info)
    update_info = f"{node_name} | {neighbor_name}"
    update_info_bytes = update_info.encode("utf-8")
    update_info_length = len(update_info_bytes)

    # Build header and packet
    header = struct.pack("!BBH", packet_type_flags, node_name_length, update_info_length)
    packet = header + node_name_bytes + update_info_bytes
    return packet


def parse_neighbor_update_packet(packet):
    """
    Parses a neighbor UPDATE packet created by create_neighbor_update_packet().
    Returns a dict:
      {
        "PacketType": <int>,
        "Flags": <int>,
        "NodeNames": ["/DLSU/Router1", "/ADMU/Router1"],
        "NeighborNames": ["/DLSU/Andrew", "/DLSU/Gokongwei"]
      }
    """
    try:
        packet_type_flags, node_name_length, info_length = struct.unpack("!BBH", packet[:4])

        # Decode node name
        node_start = 4
        node_end = node_start + node_name_length
        node_name = packet[node_start:node_end].decode("utf-8")

        # Decode update info
        info_start = node_end
        info_end = info_start + info_length
        update_info = packet[info_start:info_end].decode("utf-8")

        # Expected format: "<node_name> | <neighbor_name>"
        if "|" in update_info:
            node_part, neighbor_part = update_info.split("|", 1)
        else:
            # fallback (old format without delimiter)
            parts = update_info.split(maxsplit=1)
            node_part = parts[0] if parts else ""
            neighbor_part = parts[1] if len(parts) > 1 else ""

        # Split by spaces for multi-name support
        node_names = [n.strip() for n in node_part.strip().split() if n.strip()]
        neighbor_names = [n.strip() for n in neighbor_part.strip().split() if n.strip()]

        return {
            "PacketType": (packet_type_flags >> 4) & 0xF,
            "Flags": packet_type_flags & 0xF,
            "Name": node_names,
            "NeighborNames": neighbor_names
        }

    except Exception as e:
        print(f"[parse_neighbor_update_packet] Error parsing packet: {e}")
        return None

def parse_update_packet(packet):
    try:
        packet_type_flags, name_length, update_info_length = struct.unpack("!BBH", packet[:4])

        # Decode main name
        name_start = 4
        name_end = 4 + name_length
        name = packet[name_start:name_end].decode("utf-8")

        # Decode update info
        update_info_start = name_end
        update_info_end = update_info_start + update_info_length
        update_info = packet[update_info_start:update_info_end].decode("utf-8")

        packet_type = (packet_type_flags >> 4) & 0xF
        flags = packet_type_flags & 0xF

        # If this is a neighbor update (0x2), parse using the dedicated function
        if flags == 0x2:
            return parse_neighbor_update_packet(packet)

        # Split into components
        parts = update_info.split()

        # Format: <name> <origin_name> <next_hop_port> <number_of_hops>
        dest_name = parts[0] if len(parts) > 0 else None
        origin_name = parts[1] if len(parts) > 1 else None
        next_hop = parts[2] if len(parts) > 2 else None
        number_of_hops = int(parts[3]) if len(parts) > 3 else None

        return {
            "PacketType": (packet_type_flags >> 4) & 0xF,
            "Flags": packet_type_flags & 0xF,
            "Name": dest_name,
            "OriginName": origin_name,
            "NextHop": next_hop,
            "NumberOfHops": number_of_hops
        }

    except Exception as e:
        print(f"[parse_update_packet] Error parsing UPDATE packet: {e}")
        return None

def get_domains_from_name(node_name):
    """
    Returns a list of domains for a given node name.
    For edge nodes, splits by space and gets the topmost layer for each part.
    """
    domains = []
    for part in node_name.split(" "):
        segments = part.strip().split("/")
        if len(segments) > 1 and segments[1]:
            domains.append(segments[1])
    return domains

class Node:
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        if not hasattr(self, 'logs'):
            self.logs = []
        self.logs.append({"timestamp": timestamp, "message": message})

    def load_neighbors_from_file(self, filename):
        """
        Read neighbors.txt and for the entry matching this node's name,
        send HELLO packets to the listed ports so neighbors (including NS) learn our port.
        """
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    node_name, ports_str = line.split(':', 1)
                    node_name = node_name.strip()
                    # match exact node name (including multi-alias names)
                    if node_name != self.name:
                        continue
                    ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                    for port in ports:
                        try:
                            pkt = create_hello_packet(self.name)
                            self.sock.sendto(pkt, (self.host, int(port)))
                            print(f"[{self.name}] Sent HELLO to {self.host}:{port}")
                            self.log(f"Sent HELLO to {self.host}:{port}")
                        except Exception as e:
                            print(f"[{self.name}] Error sending HELLO to {self.host}:{port}: {e}")
                            self.log(f"Error sending HELLO to {self.host}:{port}: {e}")
        except Exception as e:
            print(f"[{self.name}] Error loading neighbors from {filename}: {e}")
            self.log(f"[{self.name}] Error loading neighbors from {filename}: {e}")

    def __init__(self, name, host="127.0.0.1", port=0, broadcast_port=9999, isborder=False):
        self.name = name
        self.domains = get_domains_from_name(name)
        self.host = host
        self.isborder = isborder
        self.port = port if port != 0 else self._get_free_port()
        self.broadcast_port = broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_sock.bind((self.host, self.broadcast_port))
        self.neighbor_table = {}
        self.last_update_received = {}

        # Tables
        self.fib = {} # {name: {"NextHops": [port, ...], "ExpirationTime": ...}}
        self.cs = {}
        self.logs = []  # List to store log entries
        # map of destination name -> list of incoming ports that sent NS-QUERY (data_flag=False)
        # so that ROUTING_DATA replies from the NameServer can be forwarded back to the requester(s)
        self.ns_query_table = {}
        self.pit = {}
        self.fragment_buffer = {}
        self.fib_interfaces = []
        self.pit_interfaces = []
        self.name_to_port = {}  # Mapping from node names to their ports

        self.log(f"Node started at {self.host}:{self.port} in domain(s): {self.domains}")

        # Start background threads for listening
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

        # Buffer and Queueing (FIFO)
        self.buffer = deque()  
        self.buffer_lock = threading.Lock()
        self.buffer_thread = threading.Thread(target=self._process_buffer_loop, daemon=True)
        self.buffer_thread.start()

        """ self.broadcast_listener_thread = threading.Thread(target=self._listen_broadcast, daemon=True)
        self.broadcast_listener_thread.start()

        self.hello_interval = 5
        self.broadcast_sender_thread = threading.Thread(target=self._send_hello_loop, daemon=True)
        self.broadcast_sender_thread.start() """

    def _handle_route_data(self, packet, addr):
        """
        Robust ROUTE_DATA handling:
         - Parse route payload and prefer forwarding toward origin via path_to_origin
         - Install FIB entries if this node appears in the provided path (so future queries use FIB)
         - Forward the raw ROUTE_DATA packet (unchanged) to the next hop's UDP port
         - Provide detailed debug output when forwarding fails
        """
        try:
            parsed = parse_route_data_packet(packet)
        except Exception as e:
            self.log(f"[{self.name}] _handle_route_data: parse error: {e}")
            return

        # canonical fields returned by parse_route_data_packet
        origin_name = parsed.get("OriginName") or (parsed.get("RoutingInfoJson") or {}).get("origin_name") if isinstance(parsed.get("RoutingInfoJson"), dict) else None
        path = parsed.get("Path") or []
        path_to_origin = parsed.get("PathToOrigin") or []
        dest = parsed.get("Dest") or parsed.get("Name")
        next_hop_field = parsed.get("NextHop")

        self.log(f"[{self.name}] Received ROUTE DATA from {addr} payload_origin={origin_name} dest={dest} path={path} path_to_origin={path_to_origin} next_hop={next_hop_field}")

        # If path is a string, normalize to list
        if isinstance(path, str):
            path = [p.strip() for p in path.split(",") if p.strip()]
        if isinstance(path_to_origin, str):
            path_to_origin = [p.strip() for p in path_to_origin.split(",") if p.strip()]

        # If this node is included in the returned path, install a FIB entry pointing to the next hop in that path
        try:
            if path and self.name in path:
                idx = path.index(self.name)
                if idx < len(path) - 1:
                    # next hop toward destination (from this node's perspective)
                    next_toward_dest = path[idx + 1]
                    port, resolved = self._resolve_port_by_name(next_toward_dest)
                    if port:
                        # install FIB so real interests will be forwarded correctly going to dest
                        self.add_fib(dest, port, exp_time=60000, hop_count=len(path) - idx - 1, source="NS")
                        self.log(f"[{self.name}] Installed FIB for {dest} -> next hop {next_toward_dest} (port {port})")
        except Exception as e:
            self.log(f"[{self.name}] Error installing FIB from ROUTE path: {e}")

        # If this ROUTE_DATA is actually intended for this node (origin of the original query)
        print(f"[{self.name}] Checking if ROUTE_DATA is for self: origin_name={origin_name}, self.name={self.name}")
        if origin_name == self.name:
            # Update FIB for the destination using provided next_hop_field if resolvable
            print("[{self.name}] ROUTE_DATA is for self; processing")
            if next_hop_field:
                port, resolved = self._resolve_port_by_name(next_hop_field)
                if port:
                    # Avoid sending to our own port (would loop back to ourselves)
                    if int(port) == int(self.port):
                        self.log(f"[{self.name}] Resolved next_hop_port == self.port ({port}); skipping send to avoid loop")
                    else:
                        try:
                            self.sock.sendto(packet, ("127.0.0.1", int(port)))
                            self.log(f"[{self.name}] Forwarded ROUTE_DATA to next_hop {resolved} (port {port})")
                        except Exception as e:
                            self.log(f"[{self.name}] Failed forwarding ROUTE_DATA to {resolved}:{port} - {e}")

            # Forward any buffered real interests for this destination
            forwarded = []
            with getattr(self, "buffer_lock", threading.Lock()):
                try:
                    for entry in list(self.buffer):
                        try:
                            parsed_interest = parse_interest_packet(entry["packet"])
                        except Exception:
                            continue
                        if parsed_interest.get("Name") == dest:
                            # decide forward using FIB entry
                            nh = self.get_next_hops(dest)
                            if nh:
                                target_port = nh
                                self.sock.sendto(entry["packet"], ("127.0.0.1", int(target_port)))
                                forwarded.append(entry)
                                self.buffer.remove(entry)
                                self.log(f"[{self.name}] Forwarded buffered interest for {dest} to port {target_port}")
                except Exception as e:
                    self.log(f"[{self.name}] Error forwarding buffered interests: {e}")
            return

        # Otherwise: we must forward this ROUTE_DATA upstream toward the origin
        next_hop_name = None
        # Prefer path_to_origin given by NS (path from NS -> origin)
        if path_to_origin:
            try:
                # find this node in the path_to_origin, then choose the next element toward the origin
                if self.name in path_to_origin:
                    idx = path_to_origin.index(self.name)
                    if idx < len(path_to_origin) - 1:
                        next_hop_name = path_to_origin[idx + 1]
                else:
                    # if node not present, but NS included itself and we are a neighbor, try to find best candidate
                    # fallback: use first element after NS if that is a neighbor of this node
                    if len(path_to_origin) > 1:
                        fallback_candidate = path_to_origin[1]
                        next_hop_name = fallback_candidate
            except Exception:
                next_hop_name = None

        # If path_to_origin did not yield a next hop, try NextHop field
        if not next_hop_name and next_hop_field:
            next_hop_name = next_hop_field

        # If still unknown, as final fallback, try to forward to origin_name directly
        if not next_hop_name:
            next_hop_name = origin_name

        # Resolve port
        if next_hop_name:
            port, resolved_name = self._resolve_port_by_name(next_hop_name)
            if port:
                try:
                    # Avoid sending to our own port (prevents self-loop)
                    if int(port) == int(self.port):
                        self.log(f"[{self.name}] Next hop resolved to own port ({port}); dropping forward to avoid loop")
                    else:
                        self.sock.sendto(packet, ("127.0.0.1", int(port)))
                        self.log(f"[{self.name}] Forwarded ROUTE_DATA to {resolved_name} (port {port})")
                except Exception as e:
                    self.log(f"[{self.name}] Error forwarding ROUTE_DATA to {resolved_name}:{port} - {e}")
            else:
                # couldn't resolve: heavy debug output to help root cause
                self.log(f"[{self.name}] Cannot resolve port for next_hop_name='{next_hop_name}'. Dumping routing state:")
                self.dump_routing_state()
                return

        # If we reach here nothing could be done
        self.log(f"[{self.name}] DROPPED ROUTE DATA for {dest}: no next_hop determined")
        self.dump_routing_state()
        return

    def _listen_broadcast(self):
        while self.running:
            try:
                data, addr = self.broadcast_sock.recvfrom(4096)
                self.receive_packet(data, addr)
            except Exception as e:
                print(f"[{self.name}] Broadcast listener stopped: {e}")
                break

    def start_neighbor_discovery(self, interval=10):
        def _send_hello_loop():
            while self.running:
                self.send_broadcast_hello()
                time.sleep(interval)
        t = threading.Thread(target=_send_hello_loop, daemon=True)
        t.start()
        return t

    def _send_hello_loop(self):
        while self.running:
            try:
                pkt = create_hello_packet(self.name)
                self.sock.sendto(pkt, ("127.0.0.1", self.broadcast_port))
                #print(f"[{self.name}] Broadcast HELLO")
            except Exception as e:
                print(f"[{self.name}] HELLO send failed: {e}")
            time.sleep(self.hello_interval)

    def _get_free_port(self):
        """Find a free port if not specified."""
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.bind(("127.0.0.1", 0))
        port = temp_sock.getsockname()[1]
        temp_sock.close()
        return port

    def _listen(self):
        """Continuously listen for incoming packets and enqueue them into the buffer before processing."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                # Log arrival first (so arrival line appears before any processing output),
                # then hand off to the processing pipeline.
                print(f"[{self.name}] Received packet from {addr}")
                # Directly hand off to the processing pipeline
                self.receive_packet(data, addr)
                # If you want to enqueue first, uncomment below and move receive out to the buffer loop:
                # with self.buffer_lock:
                # self.buffer.append({"packet": data, "addr": addr, "destination": None, "status": "waiting"})
            except Exception as e:
                print(f"[{self.name}] Listener error: {e}")
                break

    # buffer and queueing
    def add_to_buffer(self, packet, addr, reason="Unknown Destination"):
        entry = {
            "packet": packet,
            "source": self.name,
            "addr": addr,
            "destination": None,
            "status": "waiting",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "hop_history": [self.port],
            "reason": reason,
            "next_hop": None,
            "forwarded_to_ns": False
        }
        try:
            parsed = parse_interest_packet(packet)
            entry["destination"] = parsed["Name"]
        except Exception:
            entry["destination"] = "Unknown"

        with self.buffer_lock:
            self.buffer.append(entry)
        print(f"[{self.name}] Added packet to buffer (reason: {reason}). Queue size: {len(self.buffer)}")

    def _process_buffer_loop(self):
        while self.running:
            try:
                with self.buffer_lock:
                    if self.buffer:
                        # use snapshot to avoid modifying while iterating
                        snapshot = list(self.buffer)
                        for entry in snapshot:
                            try:
                                # try to detect resolved entries and forward them
                                entry_status = entry.get("status")
                                entry_dest = entry.get("dest") or entry.get("Name") or entry.get("destination")
                                next_hop = entry.get("next_hop")
                                self.log(f"BUFFER_PROC checking dest={entry_dest} status={entry_status} next_hop={next_hop}")

                                # If entry already resolved, attempt to send
                                if entry_status == "resolved" and next_hop is not None:
                                    # resolve next_hop to a port
                                    target_port = None
                                    if isinstance(next_hop, int):
                                        target_port = next_hop
                                    elif isinstance(next_hop, str):
                                        if next_hop in self.name_to_port:
                                            target_port = self.name_to_port[next_hop]
                                        else:
                                            try:
                                                target_port = int(next_hop)
                                            except Exception:
                                                target_port = None
                                    if target_port is None:
                                        self.log(f"BUFFER_PROC cannot resolve next_hop for dest={entry_dest} next_hop={next_hop}")
                                    else:
                                        try:
                                            pkt = entry.get("packet")
                                            if pkt:
                                                self.sock.sendto(pkt, (self.host, target_port))
                                                self.log(f"BUFFER_SENT dest={entry_dest} -> port={target_port}")
                                            else:
                                                self.log(f"BUFFER_NO_PACKET for dest={entry_dest}")
                                        except Exception as e:
                                            self.log(f"BUFFER_SEND_EXC dest={entry_dest} port={target_port} exc={e}")
                                        try:
                                            self.buffer.remove(entry)
                                        except ValueError:
                                            pass
                                    continue
                                elif entry_status != "resolved":
                                    self.receive_packet(entry["packet"], entry["addr"])
                                    self.buffer.remove(entry)
                            except Exception as e:
                                self.log(f"BUFFER_ENTRY_PROC_EXC: {e}")
                # sleep a bit
                time.sleep(0.1)
            except Exception as e:
                self.log(f"_process_buffer_loop EXC: {e}")

    def send_interest(self, seq_num, name, flags=0x0, target=("127.0.0.1", 0), data_flag=True):
        # Originating-interest behavior:
        # 1) If this node already has a FIB entry for the requested name, create a REAL_INTEREST
        #    (data_flag=True) and forward it directly to the FIB next hop.
        # 2) Otherwise, create an NS QUERY (data_flag=False) and send it toward the NameServer
        #    (preferably via a first-hop neighbor). In that case buffer the original interest so
        #    it can be converted to a real interest once a route is returned.

        # Useful debug: show intent
        print(f"[{self.name}] Initiating Interest for '{name}' (seq={seq_num}) origin={self.name}")
        self.log(f"Initiating Interest for '{name}' (seq={seq_num}) origin={self.name}")

        # Check routing tables for an immediate FIB hit
        table, data = self.check_tables(name)
        if table == "FIB" and data:
            # Resolve next-hop port (entry may contain int or a name)
            nh = data.get("NextHops")
            target_port = None
            try:
                # direct integer
                target_port = int(nh)
            except Exception:
                # lookup by name (aliases)
                if isinstance(nh, str) and nh in self.name_to_port:
                    try:
                        target_port = int(self.name_to_port[nh])
                    except Exception:
                        target_port = None

            if target_port:
                # Create and send a REAL_INTEREST directly
                real_pkt = create_interest_packet(seq_num, name, flags, origin_node=self.name, data_flag=True)
                try:
                    self.sock.sendto(real_pkt, (self.host, target_port))
                    print(f"[{self.name}] FIB HIT: Created REAL_INTEREST (seq={seq_num}) for '{name}' -> next_hop port {target_port}")
                    self.log(f"FIB HIT: REAL_INTEREST seq={seq_num} '{name}' -> port {target_port}")
                    # record PIT entry locally so DATA can be forwarded back (origin is self)
                    if name not in self.pit:
                        self.pit[name] = [target_port]
                        print(f"[{self.name}] Added PIT entry for '{name}' with interface [{target_port}]")
                        self.log(f"Added PIT entry for '{name}' with interface [{target_port}]")
                except Exception as e:
                    print(f"[{self.name}] ERROR sending REAL_INTEREST to port {target_port}: {e}")
                    self.log(f"ERROR sending REAL_INTEREST to port {target_port}: {e}")
                return real_pkt

        # No FIB hit → send NS QUERY (data_flag=False)
        # Build query packet (origin=self.name) — the driver/other callers might pass target NS port but
        # try to avoid sending directly to NS by choosing a first-hop neighbor if known.
        query_pkt = create_interest_packet(seq_num, name, flags, origin_node=self.name, data_flag=False)

        # Resolve whether the provided `target` looks like a NameServer port we know
        resolved_target = target
        try:
            if target and isinstance(target, (list, tuple)) and int(target[1]) != 0:
                ns_names = [n for n, p in self.name_to_port.items() if "NameServer" in n and int(p) == int(target[1])]
            else:
                ns_names = []
        except Exception:
            ns_names = []

        if ns_names:
            # prefer a neighbor first-hop toward the NS (neighbor_table keys map to names)
            first_hop_port = None
            first_hop_name = None
            for nbr in list(self.neighbor_table.keys()):
                p = self.name_to_port.get(nbr)
                if p and int(p) != int(target[1]):
                    first_hop_port = int(p)
                    first_hop_name = nbr
                    break
            # fallback: any known non-NS port
            # if not first_hop_port:
            #     for n, p in self.name_to_port.items():
            #         try:
            #             if int(p) != int(target[1]):
            #                 first_hop_port = int(p)
            #                 first_hop_name = n
            #                 break
            #         except Exception:
            #             continue
            # if first_hop_port:
            #     resolved_target = (self.host, first_hop_port)
            #     print(f"[{self.name}] NS QUERY: redirecting toward first-hop {first_hop_name} (port {first_hop_port}) instead of NS port {target[1]}")
            #     self.log(f"NS QUERY redirect -> first-hop {first_hop_name} port {first_hop_port}")

        # Send the query toward the resolved target (first-hop or NS fallback)
        try:
            # Record a PIT entry for this originated interest so that when DATA/ROUTE replies
            # arrive they can be forwarded toward the interface we used to send the query.
            try:
                pit_iface = None
                if isinstance(resolved_target, (list, tuple)) and int(resolved_target[1]) != 0:
                    pit_iface = int(resolved_target[1])
                elif isinstance(resolved_target, int):
                    pit_iface = int(resolved_target)
                if pit_iface:
                    if name not in self.pit:
                        self.pit[name] = [pit_iface]
                        print(f"[{self.name}] Added PIT entry for '{name}' with interface [{pit_iface}]")
                        self.log(f"Added PIT entry for '{name}' with interface [{pit_iface}]")
                    else:
                        if pit_iface not in self.pit[name]:
                            self.pit[name].append(pit_iface)
                            print(f"[{self.name}] Updated PIT for '{name}' with interface {pit_iface}")
                            self.log(f"Updated PIT for '{name}' with interface {pit_iface}")
            except Exception as _e:
                self.log(f"[{self.name}] Failed to add PIT entry for originated interest {name}: {_e}")

            self.add_to_buffer(query_pkt, resolved_target, reason="Originated Interest (NS query)")
            self.log(f"Buffered originated interest for '{name}' -> {resolved_target}")
            self.sock.sendto(query_pkt, resolved_target)
            print(f"[{self.name}] Sent NS QUERY (seq={seq_num}) for '{name}' to {resolved_target} (data_flag=False)")
            self.log(f"Sent NS QUERY seq={seq_num} '{name}' -> {resolved_target}")
        except Exception as e:
            print(f"[{self.name}] ERROR sending NS QUERY to {resolved_target}: {e}")
            self.log(f"ERROR sending NS QUERY to {resolved_target}: {e}")

        return query_pkt

    def send_data(self, seq_num, name, payload, flags=0x0, target=("127.0.0.1", 0)):
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
        max_payload_per_packet = FRAGMENT_SIZE - (6 + len(name.encode("utf-8")))  # header + name
        total_fragments = (len(payload_bytes) + max_payload_per_packet - 1) // max_payload_per_packet

        if len(payload_bytes) > max_payload_per_packet:
            # Fragmentation needed
            for i in range(total_fragments):
                frag_payload = payload_bytes[i*max_payload_per_packet:(i+1)*max_payload_per_packet]
                pkt = create_data_packet(seq_num, name, frag_payload, flags | TRUNC_FLAG, i+1, total_fragments)
                self.sock.sendto(pkt, target)
                print(f"[{self.name}] Sent DATA fragment {i+1}/{total_fragments} to {target}")
                self.log(f"[{self.name}] Sent DATA fragment {i+1}/{total_fragments} to {target}")
        else:
            pkt = create_data_packet(seq_num, name, payload, flags, 1, 1)
            self.sock.sendto(pkt, target)
            print(f"[{self.name}] Sent DATA packet to {target}")
            self.log(f"[{self.name}] Sent DATA packet to {target}")
        return True
    
    def add_fib(self, name, interface, exp_time, hop_count, source="HELLO"):
        try:
            norm = name
            if isinstance(name, str) and name:
                segs = name.strip('/').split('/')
                if segs:
                    last = segs[-1]
                    # treat as filename if it contains a '.' that's not leading/trailing
                    if '.' in last and not last.startswith('.') and not last.endswith('.'):
                        # remove the filename (last segment)
                        parent = '/'.join(segs[:-1])
                        norm = '/' + parent if parent else '/'
        except Exception:
            norm = name

        # interface is the next hop port (int)
        entry = {
            "NextHops": interface,
            "ExpirationTime": exp_time,
            "HopCount": hop_count,
            "Source": source
        }
        if norm not in self.fib:
            self.fib[norm] = entry
        elif norm in self.fib and hop_count < self.fib[norm]["HopCount"]:
            self.fib[norm] = entry

        #self.log(f"[{self.name}] FIB updated: {self.fib}")

    def get_next_hops(self, name):
        if name in self.fib:
            return self.fib[name]["NextHops"]
        return

    def forward_interest(self, pkt_obj, target=None):
        # If target is None, use FIB to determine next hops
        if target is None:
            next_hops = self.get_next_hops(pkt_obj.name)
            if next_hops is None:
                return
            # NextHops stored as single interface (int)
            port = next_hops
            # This is forwarding a REAL interest (to content) — ensure data_flag=True
            pkt = create_interest_packet(pkt_obj.seq_num,
                                         pkt_obj.name,
                                         pkt_obj.flags,
                                         origin_node=getattr(pkt_obj, 'origin_node', self.name),
                                         data_flag=True)
            self.sock.sendto(pkt, ("127.0.0.1", int(port)))
            print(f"[{self.name}] Forwarded INTEREST packet for {pkt_obj.name} to next hop port {port}")
            self.log(f"[{self.name}] Forwarded INTEREST packet for {pkt_obj.name} to next hop port {port}")
        else:
            # When explicitly forwarding to target, assume this is toward content => data_flag=True
            pkt = create_interest_packet(pkt_obj.seq_num,
                                         pkt_obj.name,
                                         pkt_obj.flags,
                                         origin_node=getattr(pkt_obj, 'origin_node', self.name),
                                         data_flag=True)
            self.sock.sendto(pkt, target)
            print(f"[{self.name}] Forwarded INTEREST packet to next hop port {target[1]}")
            self.log(f"[{self.name}] Forwarded INTEREST packet to next hop port {target[1]}")

    def handle_hello_from_neighbor(self, neighbor_name, addr, packet, timestamp):
        try:
            # Update neighbor tracking and mapping
            self.neighbor_table[neighbor_name] = timestamp
            self.name_to_port[neighbor_name] = addr[1]

            print(f"[{self.name}] Received REGULAR HELLO from {neighbor_name} at {addr}")
            self.log(f"[{self.name}] Received REGULAR HELLO from {neighbor_name} at {addr}")

            # --- Identify all domains this node belongs to ---
            domains = get_domains_from_name(self.name)
            if not domains:
                print(f"[{self.name}] No domains found for UPDATE to NS.")
                self.log(f"[{self.name}] No domains found for UPDATE to NS.")
                return

            # --- Notify all NameServers in each domain this node belongs to ---
            for domain in domains:
                ns_name = f"/{domain}/NameServer1"
                fib_entry = self.fib.get(ns_name)

                if fib_entry:
                    ns_port = fib_entry["NextHops"]
                    try:
                        # Create and send an update packet to inform NS of active neighbor
                        update_pkt = create_neighbor_update_packet(self.name, neighbor_name)
                        self.sock.sendto(update_pkt, ("127.0.0.1", int(ns_port)))

                        msg = (f"[{self.name}] Sent topology UPDATE to {ns_name} "
                            f"(port {ns_port}) about neighbor {neighbor_name}")
                        print(msg)
                        self.log(msg)

                    except Exception as e:
                        self.add_to_buffer(packet, addr, reason="Error sending UPDATE to NameServer")
                        print(f"[{self.name}] Error sending UPDATE to NS {ns_name}: {e}")
                        self.log(f"[{self.name}] Error sending UPDATE to NS {ns_name}: {e}")

                else:
                    # No valid FIB entry to NS — buffer packet for retry
                    self.add_to_buffer(packet, addr, reason="No FIB route to NameServer")
                    print(f"[{self.name}] No FIB entry for domain NameServer {ns_name}")
                    self.log(f"[{self.name}] No FIB entry for domain NameServer {ns_name}")

        except Exception as e:
            print(f"[{self.name}] Error handling HELLO from {neighbor_name}: {e}")
            self.log(f"[{self.name}] Error handling HELLO from {neighbor_name}: {e}")

    def receive_packet(self, packet, addr=None):
        packet_type = (packet[0] >> 4) & 0xF
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        # convenience: is this packet arriving from a known NameServer port?
        from_ns = False
        try:
            if addr is not None and self._is_ns_port(addr[1]):
                from_ns = True
        except Exception:
            from_ns = False

        if packet_type == INTEREST:
            parsed = parse_interest_packet(packet)
            # preserve the raw name as parsed from the packet (use this for ns query bookkeeping)
            raw_interest_name = parsed.get("Name")
            is_real_interest = parsed["DataFlag"]
            origin_node = parsed["OriginNode"]
            node_name = parsed.get("NodeName")
            file_name = parsed.get("FileName")
            has_filename = file_name is not None

            # --- Encapsulation handling: INTERESTs created by NameServer use the form:
            # "ENCAP:<border_alias>|<original_name>"
            # Nodes must not send encapsulated queries to their own NameServer; instead
            # forward encapsulated packet toward the border alias. When the border node
            # itself receives the ENCAP packet it strips it and continues normal processing.
            enc_layers = []
            enc_border = None
            enc_name = None

            raw_name = parsed.get("Name", "")

            if isinstance(raw_name, str) and raw_name.startswith("ENCAP:"):
                try:
                    # remove leading "ENCAP:" and split to layers
                    parts = [p.strip() for p in raw_name[6:].split("|")]

                    if len(parts) >= 2:
                        enc_layers = parts[:-1]          # all except last
                        enc_name = parts[-1]             # last = destination
                        if len(parts) >= 2:
                            enc_border = parts[-2]       # second to last = current border hop
                except Exception:
                    enc_layers = []
                    enc_border = None
                    enc_name = None

            # If ENCAP exists, override dest_name
            if enc_name:
                dest_name = enc_name

            if enc_border:
                # If this node is the border (one of its aliases), strip encapsulation and
                # treat the Interest as if its Name is the original target.
                if any(enc_border_part in self.name for enc_border_part in enc_border.split()):
                    #parsed["Name"] = enc_name
                    packet = create_interest_packet(parsed["SequenceNumber"], enc_name, parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=False)
                    is_real_interest = False
                    
                    # Record the ENCAP origin port for ack_only, so we can send ROUTE_ACK back when route is resolved
                    try:
                        # Use enc_name (original destination) as key instead of parsed["Name"] (ENCAP string)
                        key = enc_name if enc_name else parsed.get("Name")
                        if key:
                            self.ns_query_table.setdefault(key, [])
                            exists = any(item.get("port") == addr[1] for item in self.ns_query_table[key])
                            if not exists:
                                if not self._is_ns_port(addr[1]):
                                    self.ns_query_table[key].append({"port": addr[1], "ack_only": True})
                                else:
                                    self.log(f"[{self.name}] Ignored registering ack-only NS query for {key} from NS port {addr[1]}")
                    except Exception:
                        pass
                    
                    # --- Border router forwarding logic ---
                    # If this is a border node (has multiple domain aliases)
                    # and the encapsulated query came from another domain,
                    # forward the query to the NameServer of the *other* domain.
                    if " " in self.name:
                        # Border router with two domain identities
                        domain_parts = [d for d in self.name.split(" ") if d.strip()]

                        if len(domain_parts) >= 2:
                            left_domain = domain_parts[0].split("/")[1]
                            right_domain = domain_parts[1].split("/")[1]

                            # Extract visited domains from the interest packet
                            visited = set(parsed.get("VisitedDomains", []))

                            # Determine which domain has NOT been visited
                            unvisited_domains = []
                            if left_domain not in visited:
                                unvisited_domains.append(left_domain)
                            if right_domain not in visited:
                                unvisited_domains.append(right_domain)

                            # -----------------------------
                            # DECISION: which NS to contact?
                            # -----------------------------
                            if len(unvisited_domains) == 1:
                                # Perfect case: exactly one unvisited domain → forward to that NS
                                target_domain = unvisited_domains[0]

                            elif len(unvisited_domains) == 2:
                                # Neither visited yet → choose domain based on origin proximity
                                origin_domain = origin_node.split("/")[1] if "/" in origin_node else None
                                if origin_domain == left_domain:
                                    target_domain = right_domain
                                else:
                                    target_domain = left_domain

                            else:
                                # Both domains fully visited → prevent loop
                                print(f"[{self.name}] Both domains already visited ({visited}). Not querying any NS.")
                                return

                            target_ns = f"/{target_domain}/NameServer1"
                            ns_port = self.name_to_port.get(target_ns)

                            # ---------------------------------------------------------
                            # 1) If we know the NS port already → forward INTERDOMAIN
                            # ---------------------------------------------------------
                            if ns_port:
                                try:
                                    forward_pkt = create_interest_packet(
                                        parsed["SequenceNumber"],
                                        parsed["Name"],
                                        0x1,  # INTERDOMAIN flag
                                        origin_node=self.name,
                                        data_flag=False,
                                        visited_domains=list(visited)  # <-- keep visited domains
                                    )
                                    
                                    try:
                                        full_key = parsed.get("Name")
                                        if full_key:
                                            self.ns_query_table.setdefault(full_key, [])
                                            exists = any(item.get("port") == addr[1] for item in self.ns_query_table[full_key])
                                            if not exists:
                                                self.ns_query_table[full_key].append({"port": addr[1], "ack_only": True})
                                                self.log(f"[{self.name}] Registered ack-only NS query for full ENCAP name {full_key} from iface {addr[1]}")
                                                print(f"[{self.name}] Registered ack-only NS query for full ENCAP name {full_key} from iface {addr[1]}")
                                                print(f"[{self.name}] ns_query_table: {self.ns_query_table}")
                                    except Exception as e:
                                        self.log(f"[{self.name}] Error recording full ENCAP name in ns_query_table: {e}")

                                    self.sock.sendto(forward_pkt, ("127.0.0.1", int(ns_port)))
                                    print(f"[{self.name}] Forwarded interdomain interest for {parsed['Name']} → {target_ns} (port {ns_port})")
                                    self.log(f"[{self.name}] Forwarded interdomain interest → {target_ns} with visited={visited}")

                                except Exception as e:
                                    print(f"[{self.name}] Failed forwarding to {target_ns}: {e}")
                                    self.log(f"[{self.name}] Failed forwarding to {target_ns}: {e}")

                                return

                            # ---------------------------------------------------------
                            # 2) If we do NOT know the NS port → ask our own NS
                            # ---------------------------------------------------------
                            # Which domain is "ours"? The domain that matches origin
                            origin_domain = origin_node.split("/")[1] if "/" in origin_node else None
                            own_domain = left_domain if origin_domain == left_domain else right_domain
                            own_ns = f"/{own_domain}/NameServer1"

                            own_ns_port = self.name_to_port.get(own_ns)
                            if own_ns_port:
                                try:
                                    # Ask our own NS for the route to the target NS
                                    query_pkt = create_interest_packet(
                                        parsed["SequenceNumber"],
                                        target_ns,
                                        parsed["Flags"],
                                        origin_node=self.name,
                                        data_flag=False,
                                        visited_domains=list(visited)
                                    )

                                    self.sock.sendto(query_pkt, ("127.0.0.1", int(own_ns_port)))
                                    print(f"[{self.name}] Asked own NS {own_ns} for location of {target_ns}")
                                    self.log(f"[{self.name}] Asked own NS {own_ns} for target NS {target_ns}")

                                except Exception as e:
                                    print(f"[{self.name}] ERROR asking own NS {own_ns} for route to {target_ns}: {e}")
                                    self.log(f"[{self.name}] ERROR asking own NS {own_ns}: {e}")
                            return
                        
                # Try to forward directly if we already know the border port (HELLO/FIB)
                target_port = None
                if enc_border in self.name_to_port:
                    target_port = int(self.name_to_port[enc_border])
                else:
                    fib_entry = self.fib.get(enc_border)
                    if fib_entry:
                        try:
                            target_port = int(fib_entry["NextHops"])
                        except Exception:
                            target_port = None
                if target_port:
                    try:
                        if parsed["Flags"] != 0x1:
                            self.sock.sendto(packet, ("127.0.0.1", target_port))
                            self.log(f"[{self.name}] Forwarded ENCAP packet for {enc_name} toward border {enc_border} at port {target_port}")
                            print(f"[{self.name}] Forwarded ENCAP packet for {enc_name} toward border {enc_border} at port {target_port}")
                            #self.ns_query_table[parsed["Name"]].append({"port": addr[1], "ack_only": False})
                            return
                    except Exception as e:
                        self.log(f"[{self.name}] Error forwarding ENCAP to {enc_border}:{target_port} - {e}")

                if parsed["Flags"] == 0x1:
                    own_domain = self.domains[0] if self.domains else None
                    if own_domain:
                        ns_name = f"/{own_domain}/NameServer1"
                        ns_port = self.name_to_port.get(ns_name)
                        if ns_port:
                            try:
                                try:
                                    full_key = parsed.get("Name")
                                    if full_key:
                                        self.ns_query_table.setdefault(full_key, [])
                                        exists = any(item.get("port") == addr[1] for item in self.ns_query_table[full_key])
                                        if not exists:
                                            self.ns_query_table[full_key].append({"port": addr[1], "ack_only": True})
                                            self.log(f"[{self.name}] Registered ack-only NS query for full ENCAP name {full_key} from iface {addr[1]}")
                                            print(f"[{self.name}] Registered ack-only NS query for full ENCAP name {full_key} from iface {addr[1]}")
                                            print(f"[{self.name}] ns_query_table: {self.ns_query_table}")
                                except Exception as e:
                                    self.log(f"[{self.name}] Error recording full ENCAP name in ns_query_table: {e}")
                                self.sock.sendto(packet, ("127.0.0.1", int(ns_port)))
                                self.log(f"[{self.name}] Routed INTEREST with 0x1 flag to local NameServer {ns_name} at port {ns_port}")
                                print(f"[{self.name}] Routed INTEREST with 0x1 flag to local NameServer {ns_name} at port {ns_port}")
                                return
                            except Exception as e:
                                self.log(f"[{self.name}] Error routing INTEREST with 0x1 flag to local NameServer {ns_name}:{ns_port} - {e}")
                    # If no local NameServer info, buffer the packet
                    self.add_to_buffer(packet, addr, reason="No local NameServer info for INTEREST with 0x1 flag")
                    return
                
                # No direct route: ask our NameServer for the border alias, and buffer the ENCAP packet.
                # Determine local domain NameServer
                own_domain = self.domains[0] if self.domains else None
                if own_domain:
                    ns_name = f"/{own_domain}/NameServer1"
                    ns_port = None
                    fib_entry = self.fib.get(ns_name)
                    if fib_entry:
                        ns_port = fib_entry["NextHops"]
                    else:
                        ns_port = self.name_to_port.get(ns_name)

                    # Buffer the encapsulated packet so it can be forwarded when route known
                    self.add_to_buffer(packet, addr, reason=f"No route to border {enc_border} for ENCAP query (will ask NS)")

                    if ns_port:
                        # Send a separate query to local NameServer asking for the border alias
                        try:
                            # Query name = enc_border (we want NS to resolve that node)
                            query_pkt = create_interest_packet(parsed["SequenceNumber"], enc_border, parsed["Flags"], origin_node=self.name, data_flag=False)
                            self.sock.sendto(query_pkt, ("127.0.0.1", int(ns_port)))
                            self.log(f"[{self.name}] Sent NS QUERY for border {enc_border} -> {ns_name} (via port {ns_port})")
                            print(f"[{self.name}] Sent NS QUERY for border {enc_border} -> {ns_name} (via port {ns_port})")
                    
                            try:
                                # CHANGED: Use enc_name (original destination) as key instead of parsed["Name"] (ENCAP string)
                                key = enc_name if enc_name else parsed.get("Name")
                                if key:
                                    self.ns_query_table.setdefault(key, [])
                                    exists = any(item.get("port") == addr[1] for item in self.ns_query_table[key])
                                    if not exists:
                                        if not self._is_ns_port(addr[1]):
                                            self.ns_query_table[key].append({"port": addr[1], "ack_only": True})
                                            self.log(f"[{self.name}] Registered ack-only NS query for {key} from iface {addr[1]}")
                                        else:
                                            self.log(f"[{self.name}] Ignored registering ns_query_table entry from NS port {addr[1]}")
                            except Exception:
                                pass
                            
                            # mark buffered entries as having been forwarded to NS so we don't duplicate
                            with self.buffer_lock:
                                if self.buffer:
                                    # mark newest matching buffer entries
                                    for entry in reversed(self.buffer):
                                        if entry.get("destination") == parsed.get("Name") or entry.get("destination") == enc_name:
                                            entry["forwarded_to_ns"] = True
                                            break
                        except Exception as e:
                            self.log(f"[{self.name}] Error sending NS query for border {enc_border} to {ns_name}:{ns_port} - {e}")
                            # leave packet buffered and return
                    return
                # No NS info: buffer and wait (as fallback)
                self.add_to_buffer(packet, addr, reason=f"No NS to query for border {enc_border} for ENCAP query")
                return

            pkt_obj = InterestPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            # clearer logging: distinguish QUERY vs REAL INTEREST
            kind = "REAL_INTEREST" if is_real_interest else "QUERY"
            print(f"[{self.name}] Received INTEREST ({kind}) from port {addr[1]} at {timestamp} origin={origin_node}")
            self.log(f"[{self.name}] Received INTEREST from port {addr[1]} at {timestamp}")

            table, data = self.check_tables(parsed["Name"])

            # Only the originator (the node that set origin_node == self.name) should create the PIT entry
            # for its own outgoing query (data=False). For real interests (data=True) routers should
            # still maintain PIT entries so they can forward returned DATA to the requester interfaces.
            if is_real_interest or origin_node == self.name:
                if pkt_obj.name not in self.pit:
                    self.pit[pkt_obj.name] = [addr[1]]
                    print(f"[{self.name}] Added {pkt_obj.name} to PIT with interfaces: {[addr[1]]}")
                    self.log(f"[{self.name}] Added {pkt_obj.name} to PIT with interfaces: {[addr[1]]}")
                else:
                    if addr[1] not in self.pit[pkt_obj.name]:
                        self.pit[pkt_obj.name].append(addr[1])
                        print(f"[{self.name}] Updated PIT for {pkt_obj.name} with new interface: {addr[1]}")
                        self.log(f"[{self.name}] Updated PIT for {pkt_obj.name} with new interface: {addr[1]}")

            def get_node_name(name):
                # Return the node/alias that corresponds to the destination namespace.
                # For ENCAPs return the candidate border alias; otherwise return top-level or first path component.
                if not isinstance(name, str) or name == "":
                    return name

                if name.startswith("ENCAP:"):
                    try:
                        enc = name.split(":", 1)[1]
                        candidate = enc.split("|", 1)[0]
                        # candidate may contain space-separated aliases, return the first alias token
                        return candidate.split()[0]
                    except Exception:
                        pass

                # Handle normal path-like strings
                name = name.strip('/')
                if not name:
                    return '/'

                parts = name.split('/')
                last_part = parts[-1]

                # Check if the last part looks like a file (has a '.' that's not at start or end)
                if '.' in last_part and not last_part.startswith('.') and not last_part.endswith('.'):
                    # Remove the filename part
                    path_without_file = '/'.join(parts[:-1])
                    return '/' + path_without_file if path_without_file else '/'
                else:
                    # It's a folder or doesn't have an extension
                    return '/' + name
            
            def _has_asked_ns(dest_name):
                # Return True if this node has already sent an NS query for dest_name
                try:
                    with self.buffer_lock:
                        for entry in self.buffer:
                            if entry.get("destination") == dest_name and entry.get("forwarded_to_ns"):
                                return True
                except Exception:
                    pass
                return False

            # Check if destination is a direct neighbor
            neighbor_port = self.name_to_port.get(node_name)
            allow_direct = False
            if neighbor_port is not None:
                if origin_node == self.name:
                    allow_direct = True
                elif is_real_interest:
                    # permit only if we've previously queried NS for this dest or we already have a FIB
                    if parsed["Name"] in self.fib or _has_asked_ns(parsed["Name"]):
                        allow_direct = True

            if neighbor_port is not None and allow_direct:
                if has_filename:
                    # Forward directly only if there's a filename
                    role = "originator" if origin_node == self.name else "in-transit(resolved)"
                    print(f"[{self.name}] ({role}) Destination {node_name} is a direct neighbor node at port {neighbor_port}, forwarding file '{file_name}' directly.")
                    self.log(f"[{self.name}] ({role}) Destination {node_name} is a direct neighbor node at port {neighbor_port}, forwarding file '{file_name}' directly.")
                    pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=True)
                    self.sock.sendto(pkt, ("127.0.0.1", neighbor_port))
                    return
                else:
                    # Drop the interest: no filename, so no forwarding
                    # Create and send DROPPED_ERROR packet to PIT interfaces
                    error_pkt = create_error_packet(parsed["SequenceNumber"], parsed["Name"], DROPPED_ERROR, origin_node=origin_node)
                    pit_ifaces = self.pit.get(parsed["Name"], [])
                    if pit_ifaces:
                        for iface_port in list(pit_ifaces):
                            self.log(f"[{self.name}] Sent DROPPED_ERROR for '{parsed['Name']}' to PIT iface {iface_port}")
                            print(f"[{self.name}] Sent DROPPED_ERROR for '{parsed['Name']}' to PIT iface {iface_port}")
                            self.sock.sendto(error_pkt, ("127.0.0.1", int(iface_port)))
                        self.remove_pit(parsed["Name"])
                    else:
                        # fallback: send to requester if PIT is missing
                        self.sock.sendto(error_pkt, addr)
                        self.log(f"[{self.name}] Sent DROPPED_ERROR for '{parsed['Name']}' to {addr} (no PIT entry)")
                        print(f"[{self.name}] Sent DROPPED_ERROR for '{parsed['Name']}' to {addr} (no PIT entry)")
                    self.log(f"[{self.name}] Dropped interest for {node_name} as it's a direct neighbor without filename")
                    print(f"[{self.name}] Dropped interest for {node_name} as it's a direct neighbor without filename")
                return
            # Otherwise do not forward directly here; let the normal NS-query path handle it.

            # If this is a query to the NameServer (data_flag == False)
            if not is_real_interest:
                # Registering "ns_query_table" entries must NOT record NameServer ports.
                # If this packet came from a NameServer port, skip creating requester-face entries.
                if from_ns:
                    self.log(f"[{self.name}] Ignoring ns_query_table registration for query '{raw_interest_name}' arriving from NS port {addr[1]}")
                else:
                    # existing code path will register ns_query_table entries — ensure it uses the guarded helper (below)
                    pass

                # --- Ensure an NS-query "PIT" is created for ENCAP and related name forms ---
                # Record multiple keys so ROUTE_ACK (which may carry either the full ENCAP
                # name or the inner original name) finds the correct incoming iface.
                try:
                    port = addr[1] if addr else None
                    if port is not None:
                        def _add_ns_query_key(k):
                            if not k:
                                return
                            lst = self.ns_query_table.setdefault(k, [])
                            if not any(item.get("port") == port for item in lst):
                                if not self._is_ns_port(port):
                                    lst.append({"port": port, "ack_only": bool(parsed.get("Flags", 0) & ACK_FLAG)})
                                    self.log(f"[{self.name}] ns_query_table[{k}] add iface {port}")
                                    print(f"[{self.name}] ns_query_table[{k}] add iface {port}")
                                else:
                                    self.log(f"[{self.name}] Ignored registering NS-query key {k} for NS port {port}")

                        # add full key exactly as received
                        _add_ns_query_key(raw_interest_name)

                        # If ENCAP form, also index the inner name and border alias forms
                        if isinstance(raw_interest_name, str) and raw_interest_name.startswith("ENCAP:"):
                            try:
                                rest = raw_interest_name[6:]
                                border_alias, inner_name = rest.split("|", 1)
                                border_alias = border_alias.strip()
                                inner_name = inner_name.strip()
                                _add_ns_query_key(inner_name)          # inner original name
                                _add_ns_query_key(border_alias + "|" + inner_name)  # normalized encap fragment
                            except Exception:
                                pass
                except Exception as e:
                    self.log(f"[{self.name}] Error recording NS-query PIT: {e}")

                # --- Record NS-query PIT entry for ENCAP or regular NS queries ---
                # When an ENCAP query traverses this node (or any NS-query arrives),
                # record the incoming interface under the exact packet name so that
                # future ROUTE_ACKs can be forwarded along the reverse path.
                try:
                    key = raw_interest_name  # exact packet name as received (preserves ENCAP wrapper)
                    if key:
                        self.ns_query_table.setdefault(key, [])
                        # avoid duplicate same-port entries
                        if not any(item.get("port") == addr[1] for item in self.ns_query_table[key]):
                            if not self._is_ns_port(addr[1]):
                                self.ns_query_table[key].append({"port": addr[1], "ack_only": True})
                            else:
                                self.log(f"[{self.name}] Ignored registering NS-query PIT key {key} from NS port {addr[1]}")
                except Exception as e:
                    self.log(f"[{self.name}] Error recording NS-query PIT: {e}")


                own_domain = self.domains[0] if self.domains else None
                if own_domain:
                    ns_name = f"/{own_domain}/NameServer1"
                    fib_entry = self.fib.get(ns_name)
                    if fib_entry:
                        ns_port = fib_entry["NextHops"]
                        try:
                            self.sock.sendto(packet, ("127.0.0.1", int(ns_port)))
                            self.log(f"[{self.name}] Forwarded NS QUERY for {parsed['Name']} -> {ns_name} (via port {ns_port}) origin={origin_node}")
                        except Exception as e:
                            self.log(f"[{self.name}] Error forwarding NS query to {ns_name}: {e}")
                        return
                    
                def _top_domain(fullname):
                    if not fullname:
                        return None
                    segs = fullname.strip('/').split('/')
                    return segs[0] if segs and segs[0] else None

                origin_domain = _top_domain(origin_node)
                target_domain = _top_domain(parsed["Name"])

                # If this node is a border router (it contains multiple space-separated names),
                # and origin/target domains differ, forward the query to the NameServer of the
                # target domain.
                if " " in self.name and origin_domain and target_domain and origin_domain != target_domain:
                    ns_name = f"/{target_domain}/NameServer1"
                    pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=False)

                    # Preferred: direct send if we already know the NameServer port
                    ns_port = self.name_to_port.get(ns_name)
                    if ns_port:
                        try:
                            self.sock.sendto(pkt, ("127.0.0.1", ns_port))
                            self.log(f"[{self.name}] FORWARDED QUERY -> {ns_name} (port {ns_port}) for {parsed['Name']} from {origin_node}")
                            print(f"[{self.name}] Forwarded QUERY for {parsed['Name']} to {ns_name} at port {ns_port}")
                            return
                        except Exception as e:
                            self.log(f"[{self.name}] Forward-to-NS failed: {e}")

                    # Fallback: forward to any neighbor that belongs to the target domain (using neighbor names)
                    forwarded = False
                    for neighbor_name in list(self.neighbor_table.keys()):
                        neighbor_domains = get_domains_from_name(neighbor_name)
                        if target_domain in neighbor_domains:
                            neighbor_port = self.name_to_port.get(neighbor_name)
                            if neighbor_port:
                                try:
                                    self.sock.sendto(pkt, ("127.0.0.1", neighbor_port))
                                    self.log(f"[{self.name}] FORWARDED QUERY -> neighbor {neighbor_name} (port {neighbor_port}) for {parsed['Name']}")
                                    print(f"[{self.name}] Forwarded QUERY for {parsed['Name']} to neighbor {neighbor_name} at port {neighbor_port}")
                                    forwarded = True
                                    break
                                except Exception as e:
                                    self.log(f"[{self.name}] Forward-to-neighbor failed: {e}")
                    if forwarded:
                        return

                # Non-border or couldn't resolve NS: if we know any NameServer for the target domain, use it
                if target_domain:
                    for known_name, known_port in list(self.name_to_port.items()):
                        if known_name.startswith(f"/{target_domain}/") and "NameServer" in known_name:
                            pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=False)
                            try:
                                self.sock.sendto(pkt, ("127.0.0.1", known_port))
                                self.log(f"[{self.name}] FORWARDED QUERY -> {known_name} (port {known_port}) for {parsed['Name']}")
                                print(f"[{self.name}] Forwarded QUERY for {parsed['Name']} to {known_name} at port {known_port}")
                                return
                            except Exception as e:
                                self.log(f"[{self.name}] Forward-to-known-NS failed: {e}")
                # otherwise fall through to default handling (buffering / ask NS later)
                # If no domain/FIB to NS, buffer the query (fallback)

                self.add_to_buffer(packet, addr, reason="No FIB route to NS for data=False query")
                return  # done for data=False packets

            # From here: is_real_interest == True (this is the "real" Interest for the file)
            # If we don't have CS or FIB entry, buffer the real interest and ask the NS on behalf of this node.
            if table is None or table == "PIT":
                # Before buffering and creating a NameServer query for a REAL interest,
                # re-check whether destination is a direct neighbor and forward directly if so.
                # Allow direct-forward when this node itself is directly connected to the destination
                # (special-case: node is adjacent to the dest) — this executes only in the pre-NS path.
                if is_real_interest:
                    node_name = get_node_name(parsed["Name"])
                    print(f"[{self.name}] node_name: {node_name} extracted from Interest name {parsed['Name']}")
                    neighbor_port = self.name_to_port.get(node_name)
                    if neighbor_port is not None:
                        # direct-adjacent: forward straight to neighbor (no NS query needed)
                        print(f"[{self.name}] (pre-NS) Destination {parsed['Name']} is a direct neighbor {node_name} at port {neighbor_port}, forwarding directly (real interest).")
                        self.log(f"[{self.name}] (pre-NS) Destination {parsed['Name']} is a direct neighbor {node_name} at port {neighbor_port}, forwarding directly (real interest).")
                        pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=True)
                        self.sock.sendto(pkt, ("127.0.0.1", int(neighbor_port)))
                        return
                    # Insert error packet logic: if this node is the target and file not found in CS, return error
                    if node_name == self.name and has_filename and file_name:
                        found = False
                        for cs_key in self.cs.keys():
                            if cs_key == parsed["Name"] or cs_key.endswith('/' + file_name) or cs_key == file_name:
                                found = True
                                break
                        if not found:
                            error_pkt = create_error_packet(parsed["SequenceNumber"], parsed["Name"], NO_DATA_ERROR, origin_node=origin_node)
                            pit_ifaces = self.pit.get(parsed["Name"], [])
                            if pit_ifaces:
                                for iface_port in list(pit_ifaces):
                                    self.sock.sendto(error_pkt, ("127.0.0.1", int(iface_port)))
                                    self.log(f"[{self.name}] Sent ERROR (Data Not Found) for '{file_name}' to PIT iface {iface_port}")
                                    print(f"[{self.name}] Sent ERROR (Data Not Found) for '{file_name}' to PIT iface {iface_port}")
                                self.remove_pit(parsed["Name"])
                            else:
                                # fallback: send to requester if PIT is missing
                                self.sock.sendto(error_pkt, addr)
                                self.log(f"[{self.name}] Sent ERROR (Data Not Found) for '{file_name}' to {addr} (no PIT entry)")
                                print(f"[{self.name}] Sent ERROR (Data Not Found) for '{file_name}' to {addr} (no PIT entry)")
                            return
                # else: fall through to existing buffering + NS query logic

                # Buffer the real interest (so it can be forwarded to the next hop once known)
                self.add_to_buffer(packet, addr, reason="No FIB route available for real interest (data=True)")
                # Now check if we've already sent a query for this Interest to the NS
                already_asked_ns = False
                with self.buffer_lock:
                    # Only check the most recent (last) buffer entry for this destination
                    for entry in reversed(self.buffer):
                        if entry["destination"] == parsed["Name"]:
                            already_asked_ns = entry.get("forwarded_to_ns", False)
                            break
                if not already_asked_ns:
                    # -----------------------------------------------------------
                    # If NOT a border router → use existing behavior
                    # -----------------------------------------------------------
                    own_domain = self.domains[0] if self.domains else None
                    if own_domain and not self.isborder:
                        ns_name = f"/{own_domain}/NameServer1"
                        fib_entry = self.fib.get(ns_name)
                        ns_port = fib_entry["NextHops"] if fib_entry else self.name_to_port.get(ns_name)

                        if ns_port:
                            try:
                                query_pkt = create_interest_packet(
                                    parsed["SequenceNumber"], parsed["Name"], parsed["Flags"],
                                    origin_node=self.name, data_flag=False
                                )
                                self.sock.sendto(query_pkt, ("127.0.0.1", int(ns_port)))
                                print(f"[{self.name}] Sent NS QUERY for {parsed['Name']} -> {ns_name} via port {ns_port}")
                                self.log(f"[{self.name}] Sent NS QUERY for {parsed['Name']} -> {ns_name} via port {ns_port}")
                                # mark buffered
                                with self.buffer_lock:
                                    for entry in self.buffer:
                                        if entry.get("destination") == parsed["Name"]:
                                            entry["forwarded_to_ns"] = True
                            except Exception as e:
                                print(f"[{self.name}] Error forwarding INTEREST query to NS: {e}")
                        else:
                            print(f"[{self.name}] No route to NameServer {ns_name}")
                        return

                    # -----------------------------------------------------------
                    # Border router logic (self.isborder == True)
                    # -----------------------------------------------------------
                    if self.isborder:
                        # Example: /DLSU/Router1 /ADMU/Router1
                        # Determine target domain based on the Interest name
                        interest_full = parsed["Name"].lstrip("/")
                        parts = interest_full.split("/")
                        target_domain = parts[0] if parts else None

                        # Determine border router's two domains
                        # e.g. ["DLSU", "ADMU"]
                        border_domains = []
                        for alias in self.name.split():
                            alias = alias.strip("/")
                            segs = alias.split("/")
                            if segs and len(segs) > 1:
                                border_domains.append(segs[0])

                        border_domains = list(set(border_domains))
                        # example: border_domains = ["DLSU", "ADMU"]

                        # Last domain visited = domain of the node that sent packet to this router
                        last_domain = None
                        if parsed["OriginNode"] and "/" in parsed["OriginNode"]:
                            last_domain = parsed["OriginNode"].split("/")[1]

                        # -------------------------------------------------------
                        # 1. If target domain has a known NS → send to that NS
                        # -------------------------------------------------------
                        if target_domain:
                            target_ns = f"/{target_domain}/NameServer1"
                            target_ns_port = self.name_to_port.get(target_ns)

                            if target_ns_port:
                                try:
                                    pkt = create_interest_packet(
                                        parsed["SequenceNumber"],
                                        parsed["Name"],
                                        parsed["Flags"],
                                        origin_node=self.name,
                                        data_flag=False
                                    )
                                    self.sock.sendto(pkt, ("127.0.0.1", int(target_ns_port)))
                                    print(f"[{self.name}] BORDER NS QUERY → {target_ns} for {parsed['Name']}")
                                    self.log(f"[{self.name}] BORDER NS QUERY → {target_ns} for {parsed['Name']}")
                                    # mark buffered
                                    with self.buffer_lock:
                                        for entry in self.buffer:
                                            if entry.get("destination") == parsed["Name"]:
                                                entry["forwarded_to_ns"] = True
                                except Exception as e:
                                    print(f"[{self.name}] Border NS query failed: {e}")
                                return

                        # -------------------------------------------------------
                        # 2. If no target domain match, send to the NS we HAVEN'T visited
                        # -------------------------------------------------------
                        alt_domain = None
                        for dom in border_domains:
                            if dom != last_domain:  # choose the domain not visited
                                alt_domain = dom
                                break

                        if alt_domain:
                            alt_ns = f"/{alt_domain}/NameServer1"
                            alt_ns_port = self.name_to_port.get(alt_ns)
                            if alt_ns_port:
                                try:
                                    pkt = create_interest_packet(
                                        parsed["SequenceNumber"],
                                        parsed["Name"],
                                        parsed["Flags"],
                                        origin_node=self.name,
                                        data_flag=False
                                    )
                                    self.sock.sendto(pkt, ("127.0.0.1", int(alt_ns_port)))
                                    print(f"[{self.name}] BORDER NS QUERY (fallback) → {alt_ns} for {parsed['Name']}")
                                    self.log(f"[{self.name}] BORDER NS QUERY (fallback) → {alt_ns} for {parsed['Name']}")
                                    # mark buffered
                                    with self.buffer_lock:
                                        for entry in self.buffer:
                                            if entry.get("destination") == parsed["Name"]:
                                                entry["forwarded_to_ns"] = True
                                except Exception as e:
                                    print(f"[{self.name}] Border NS fallback query failed: {e}")
                                return

                        # -------------------------------------------------------
                        # 3. No NS found → keep buffered
                        # -------------------------------------------------------
                        print(f"[{self.name}] BORDER: No suitable NS found for {parsed['Name']}")
                        self.log(f"[{self.name}] BORDER: No suitable NS found for {parsed['Name']}")
                        return

            elif table == "CS":
                print(f"[{self.name}] Data found in CS for {parsed['Name']}, sending DATA back to {addr}")
                self.log(f"[{self.name}] Data found in CS for {parsed['Name']}, sending DATA back to {addr}")
                self.remove_pit(pkt_obj.name, addr[1])
                self.send_data(
                    seq_num=pkt_obj.seq_num,
                    name=pkt_obj.name,
                    payload=data,
                    flags=ACK_FLAG,
                    target=addr
                )
            elif table == "FIB":
                next_hop = data["NextHops"]
                print(f"[{self.name}] Forwarding INTEREST for {parsed['Name']} via FIB to next hop port: {next_hop}")
                self.log(f"[{self.name}] Forwarding INTEREST for {parsed['Name']} via FIB to next hop port: {next_hop}")
                # Protect against installing a FIB that points back to the incoming interface
                try:
                    nh_port = int(next_hop)
                except Exception:
                    # try resolve if stored as name
                    nh_port = None
                    if isinstance(next_hop, str) and next_hop in self.name_to_port:
                        try:
                            nh_port = int(self.name_to_port[next_hop])
                        except Exception:
                            nh_port = None

                # If the FIB next-hop equals the incoming interface, avoid ping-pong:
                # buffer the real interest and ask local NameServer for a proper route.
                incoming_port = addr[1] if addr else None
                if nh_port is not None and incoming_port is not None and nh_port == incoming_port:
                    self.log(f"[{self.name}] FIB next-hop {nh_port} == incoming iface {incoming_port}; buffering and querying NS to avoid ping-pong")
                    self.add_to_buffer(packet, addr, reason="FIB loop detected (next hop == incoming iface)")

                    # Check if we've already asked NS for this destination
                    already_asked_ns = False
                    with self.buffer_lock:
                        for entry in reversed(self.buffer):
                            if entry.get("destination") == parsed["Name"]:
                                already_asked_ns = entry.get("forwarded_to_ns", False)
                                break

                    if not already_asked_ns:
                        own_domain = self.domains[0] if self.domains else None
                        if own_domain:
                            ns_name = f"/{own_domain}/NameServer1"
                            fib_entry = self.fib.get(ns_name)
                            ns_port = None
                            if fib_entry:
                                ns_port = fib_entry["NextHops"]
                            else:
                                ns_port = self.name_to_port.get(ns_name)

                            if ns_port:
                                try:
                                    query_pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=self.name, data_flag=False)
                                    self.sock.sendto(query_pkt, ("127.0.0.1", int(ns_port)))
                                    self.log(f"[{self.name}] Sent NS QUERY for {parsed['Name']} (origin={self.name}) -> {ns_name} via port {ns_port} due to FIB loop avoidance")
                                    with self.buffer_lock:
                                        for entry in self.buffer:
                                            if entry.get("destination") == parsed["Name"]:
                                                entry["forwarded_to_ns"] = True
                                except Exception as e:
                                    self.log(f"[{self.name}] Error sending NS query for {parsed['Name']} due to FIB loop: {e}")
                    return

                # Normal forwarding if no loop detected
                if nh_port is not None:
                    self.forward_interest(pkt_obj, ("127.0.0.1", nh_port))
                else:
                    # fallback: try to forward using string next_hop as name mapping or call forward_interest default
                    if isinstance(next_hop, str) and next_hop in self.name_to_port:
                        try:
                            self.forward_interest(pkt_obj, ("127.0.0.1", int(self.name_to_port[next_hop])))
                        except Exception:
                            # final fallback: use forward_interest without explicit target
                            self.forward_interest(pkt_obj)
                    else:
                        self.forward_interest(pkt_obj)
            return pkt_obj


        elif packet_type == DATA:
            parsed = parse_data_packet(packet)
            pkt_obj = DataPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                payload=parsed["Payload"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            frag_key = (parsed["SequenceNumber"], parsed["Name"])
            name = parsed["Name"]

            # Fragmentation handling for large DATA
            if parsed["TotalFragments"] > 1:
                if frag_key not in self.fragment_buffer:
                    self.fragment_buffer[frag_key] = [None] * parsed["TotalFragments"]
                self.fragment_buffer[frag_key][parsed["FragmentNum"]-1] = parsed["Payload"]
                self.log(f"Received DATA fragment {parsed['FragmentNum']}/{parsed['TotalFragments']} from {addr}")
                if all(frag is not None for frag in self.fragment_buffer[frag_key]):
                    full_payload = ''.join(self.fragment_buffer[frag_key])
                    self.log(f"All fragments received. Reassembled payload: {full_payload}")
                    self.add_cs(name, full_payload)
                    # forward to PIT interfaces
                    if name in self.pit:
                        interfaces = list(self.pit[name])
                        for interface in interfaces:
                            # Skip forwarding back to the interface that sent this DATA (avoid loop/duplicate)
                            try:
                                incoming_port = addr[1] if addr else None
                            except Exception:
                                incoming_port = None

                            if incoming_port is not None and int(interface) == int(incoming_port):
                                # remove the PIT entry but do not forward to the sender
                                self.remove_pit(name, interface)
                                self.log(f"[{self.name}] Skipped forwarding reassembled DATA back to incoming iface {interface}")
                                continue

                            self.remove_pit(name, interface)
                            pkt = create_data_packet(parsed["SequenceNumber"], name, full_payload, parsed["Flags"], 1, 1)
                            self.sock.sendto(pkt, (self.host, interface))
                            self.log(f"Forwarded reassembled DATA to PIT interface {interface}")
                    del self.fragment_buffer[frag_key]
            else:
                # Regular DATA from destination: add to CS and forward using PIT
                self.log(f"Received DATA from {addr} at {timestamp}")
                self.log(f"Parsed: {parsed}")
                self.log(f"Object: {pkt_obj}")
                
                print(f"Received DATA from {addr} at {timestamp}")
                print(f"Parsed: {parsed}")
                print(f"Object: {pkt_obj}")
                self.add_cs(name, parsed["Payload"])
                if name in self.pit:
                    interfaces = list(self.pit[name])
                    for interface in interfaces:
                        # Avoid forwarding DATA back to the interface it arrived from (prevents duplicate delivery)
                        try:
                            incoming_port = addr[1] if addr else None
                        except Exception:
                            incoming_port = None

                        if incoming_port is not None and int(interface) == int(incoming_port):
                            # remove PIT entry but don't send back to sender
                            self.remove_pit(name, interface)
                            self.log(f"[{self.name}] Skipped forwarding DATA back to incoming iface {interface}")
                            continue

                        self.remove_pit(name, interface)
                        pkt = create_data_packet(parsed["SequenceNumber"], name, parsed["Payload"], parsed["Flags"], 1, 1)
                        self.sock.sendto(pkt, (self.host, interface))
                        self.log(f"Forwarded DATA to PIT interface {interface}")

            return pkt_obj

        elif packet_type == HELLO:
            parsed = parse_hello_packet(packet)
            neighbor_name = parsed["Name"]
            self.neighbor_table[neighbor_name] = timestamp
            self.name_to_port[neighbor_name] = addr[1]
            print(f"[{self.name}] Received HELLO from {neighbor_name} at {addr}")
            self.log(f"[{self.name}] Received HELLO from {neighbor_name} at {addr}")

            if parsed["Flags"] == 0x0:
                sender_domains = get_domains_from_name(neighbor_name)
                ns_update_packet = create_ns_update_packet(neighbor_name, self.name, addr[1], 1)
                self.send_ns_update_to_domain_neighbors(neighbor_name, sender_domains, 
                                                        ns_update_packet, exclude_port=addr[1])
                self.handle_hello_from_neighbor(neighbor_name, addr, packet, timestamp)
            elif parsed["Flags"] == 0x1:
                self.handle_hello_from_neighbor(neighbor_name, addr, packet, timestamp)

            # Add neighbor to FIB
            self.add_fib(neighbor_name, addr[1], exp_time=5000, hop_count=1)

        elif packet_type == ROUTE_ACK:
            parsed_ack = parse_route_ack_packet(packet)
            if not parsed_ack:
                self.log(f"[{self.name}] Failed to parse ROUTE_ACK from {addr}")
                return
            
            # Use the full packet name (which may be ENCAP:<border>|<original>) as the lookup key
            dest_name = parsed_ack.get("Name")
            self.log(f"[{self.name}] Received ROUTE_ACK for {dest_name} from {addr}")
            print(f"[{self.name}] Received ROUTE_ACK for {dest_name} from {addr}")

            # Forward the ack toward all recorded NS-query interfaces (propagate ack upstream)
            # Try exact lookup first, then tolerant matches (handles stripped vs full-encap keys).
            pending = self.ns_query_table.get(dest_name)
            matched_key = dest_name
            if not pending:
                # attempt inner-name and ENCAP-normalized matches
                for k, v in list(self.ns_query_table.items()):
                    if not isinstance(k, str):
                        continue
                    # direct exact match
                    if k == dest_name:
                        pending = v
                        matched_key = k
                        break
                    # ENCAP key that ends with "|<dest>"
                    if k.endswith("|" + dest_name):
                        pending = v
                        matched_key = k
                        break
                    # if dest is inner part of an ENCAP key
                    if k.startswith("ENCAP:") and "|" in k:
                        try:
                            _, inner = k.split("|", 1)
                            inner = inner.strip()
                            if inner == dest_name:
                                pending = v
                                matched_key = k
                                break
                        except Exception:
                            pass
                    # substring fallback (defensive)
                    if dest_name in k:
                        pending = v
                        matched_key = k
                        break
            if pending:
                for entry in list(pending):
                    try:
                        p = int(entry.get("port"))
                        self.sock.sendto(packet, ("127.0.0.1", p))
                        self.log(f"[{self.name}] Forwarded ROUTE_ACK for {dest_name} to iface port {p}")
                        print(f"[{self.name}] Forwarded ROUTE_ACK for {dest_name} to iface port {p}")
                    except Exception as e:
                        self.log(f"[{self.name}] Error forwarding ROUTE_ACK to iface {entry}: {e}")
                # remove the recorded PIT for this matched key so subsequent acks don't reuse stale mapping
                try:
                    del self.ns_query_table[matched_key]
                except KeyError:
                    pass
                return

            # NEW: If no pending recorded interfaces, forward to own NameServer by default (best-effort)
            own_domain = self.domains[0] if self.domains else None
            if own_domain:
                ns_name = f"/{own_domain}/NameServer1"
                ns_port = self.name_to_port.get(ns_name)
                # try FIB fallback if name_to_port doesn't have exact mapping
                if ns_port is None:
                    fib_entry = self.fib.get(ns_name)
                    if fib_entry:
                        ns_port = fib_entry.get("NextHops")
                if ns_port:
                    try:
                        self.sock.sendto(packet, ("127.0.0.1", int(ns_port)))
                        self.log(f"[{self.name}] Forwarded ROUTE_ACK for {dest_name} to own NS {ns_name} at port {ns_port}")
                        print(f"[{self.name}] Forwarded ROUTE_ACK for {dest_name} to own NS {ns_name} at port {ns_port}")
                        return
                    except Exception as e:
                        self.log(f"[{self.name}] Error forwarding ROUTE_ACK to own NS: {e}")

            # If no NS to forward to, drop as before
            self.log(f"[{self.name}] No pending NS-query interfaces or NS for ROUTE_ACK {dest_name}; dropping")
            return

        elif packet_type == UPDATE:
            parsed = parse_update_packet(packet)
            neighbor_name = parsed["Name"]
            self.log(f"[{self.name}] Received UPDATE from {neighbor_name} at {addr} with parsed data: {parsed}")
            #print(f"[{self.name}] Received UPDATE from {neighbor_name} at {addr} with parsed data: {parsed}")
            if parsed["Flags"] == 0x1:
                # BAND-AID SOLUTION, prevent update flooding by adding cooldown
                now = time.time()
                cooldown = 10  # seconds
                last_time = self.last_update_received.get(neighbor_name, 0)
                if now - last_time < cooldown:
                    # Ignore NS UPDATE if within cooldown
                    #print(f"[{self.name}] Ignored NS UPDATE from {neighbor_name} due to cooldown.")
                    return
                self.last_update_received[neighbor_name] = now
                sender_domains = get_domains_from_name(neighbor_name)
                hops = parsed["NumberOfHops"] + 1 if parsed["NumberOfHops"] else 1
                ns_update_packet = create_ns_update_packet(neighbor_name, self.name, self.port, hops)
                self.send_ns_update_to_domain_neighbors(neighbor_name, sender_domains, 
                                                        ns_update_packet, exclude_port=addr[1])
                self.add_fib(neighbor_name, addr[1], exp_time=5000, hop_count=hops)
                self.name_to_port[neighbor_name] = addr[1]
            elif parsed["Flags"] == 0x2:
                # --- Handle NEIGHBOR UPDATE packets (forward to NameServer(s)) ---
                parsed = parse_neighbor_update_packet(packet)
                if not parsed:
                    print(f"[{self.name}] Failed to parse NEIGHBOR UPDATE packet from {addr}")
                    return

                node_names = parsed.get("Name", [])
                neighbor_names = parsed.get("NeighborNames", [])

                if not node_names or not neighbor_names:
                    print(f"[{self.name}] Invalid NEIGHBOR UPDATE: missing node or neighbor names from {addr}")
                    return

                print(f"[{self.name}] Received NEIGHBOR UPDATE packet at {addr}")
                print(f"    [{self.name}] Node(s): {node_names}")
                print(f"    [{self.name}] Neighbor(s): {neighbor_names}")
                self.log(f"[{self.name}] Received NEIGHBOR UPDATE for {node_names} -> {neighbor_names} at {addr}")

                # Determine this node's domains (for multi-domain/border routers)
                domains = get_domains_from_name(self.name)
                if not domains:
                    print(f"[{self.name}] No domain(s) found for forwarding neighbor update to NS.")
                    self.log(f"[{self.name}] No domain(s) found for forwarding neighbor update to NS.")
                    return

                # Forward updates to all relevant NameServers in this node's domains
                for domain in domains:
                    ns_name = f"/{domain}/NameServer1"
                    fib_entry = self.fib.get(ns_name)
                    if not fib_entry:
                        self.add_to_buffer(packet, addr, reason=f"No FIB route to NameServer {ns_name}")
                        print(f"[{self.name}] No FIB entry for NameServer {ns_name} — buffering NEIGHBOR UPDATE.")
                        self.log(f"[{self.name}] No FIB entry for NameServer {ns_name} — buffering NEIGHBOR UPDATE.")
                        continue

                    ns_port = fib_entry["NextHops"]

                    try:
                        # Build combined multi-name packet for all node–neighbor pairs
                        combined_node_name = " ".join(node_names)
                        combined_neighbor_name = " ".join(neighbor_names)
                        forward_pkt = create_neighbor_update_packet(combined_node_name, combined_neighbor_name)

                        # Send packet to this domain's NameServer
                        self.sock.sendto(forward_pkt, ("127.0.0.1", int(ns_port)))

                        print(f"[{self.name}] Forwarded NEIGHBOR UPDATE to {ns_name} (port {ns_port}) "
                            f"for nodes: {combined_node_name} -> {combined_neighbor_name}")
                        self.log(f"[{self.name}] Forwarded NEIGHBOR UPDATE to {ns_name} (port {ns_port}) "
                                f"for nodes: {combined_node_name} -> {combined_neighbor_name}")

                    except Exception as e:
                        # If sending fails, add packet to buffer
                        self.add_to_buffer(packet, addr, reason=f"Failed to forward NEIGHBOR UPDATE to NS {ns_name}")
                        print(f"[{self.name}] Error forwarding NEIGHBOR UPDATE to {ns_name}: {e}")
                        self.log(f"[{self.name}] Error forwarding NEIGHBOR UPDATE to {ns_name}: {e}")

        elif packet_type == ROUTING_DATA:
            parsed = parse_route_data_packet(packet)
            pkt_obj = RouteDataPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                flags=parsed["Flags"],
                timestamp=timestamp,
                path=parsed.get("Path", []),
                raw_routing_info=parsed.get("RawRoutingInfo", "")
            )
            print(f"[{self.name}] Received ROUTE DATA from {addr} at {timestamp}")
            self.log(f"[{self.name}] Received ROUTE DATA from {addr} at {timestamp}")

            origin_name = parsed.get("OriginName")
            route_info = parsed.get("RoutingInfoJson")
            dest_name = parsed.get("Name")

            # Alias-aware port resolution
            def _resolve_port_by_name(self, name_str):
                """
                Resolve a node-name (may be space-separated aliases) to a known port.
                Tries, in order:
                - exact match in self.name_to_port
                - any alias token in name_str found in name_to_port
                - neighbor_table keys (exact or alias tokens)
                - strip last level (parent) and try again
                Returns (port:int or None, resolved_name:str or None)
                """
                if not name_str:
                    return None, None
                # exact
                if name_str in self.name_to_port:
                    return self.name_to_port[name_str], name_str
                # token aliases in the string
                for token in name_str.split():
                    if token in self.name_to_port:
                        return self.name_to_port[token], token
                # neighbors table (may contain alias forms)
                for nbr in list(self.neighbor_table.keys()):
                    if nbr == name_str:
                        return self.name_to_port.get(nbr), nbr
                    for token in nbr.split():
                        if token == name_str or token in name_str.split():
                            return self.name_to_port.get(nbr), nbr
                # try parent (strip last level)
                if '/' in name_str:
                    parent = '/' + '/'.join(name_str.strip('/').split('/')[:-1])
                    if parent in self.name_to_port:
                        return self.name_to_port[parent], parent
                    for token in parent.split():
                        if token in self.name_to_port:
                            return self.name_to_port[token], token
                return None, None

            # Only process if origin_name matches this node
            if origin_name == self.name:
                # extract destination and next hop (port or name) from reply
                dest = None
                next_hop = None
                next_hop_port = None
                if isinstance(route_info, dict):
                    dest = route_info.get("dest") or parsed.get("Name")
                    next_hop = route_info.get("next_hop") or parsed.get("NextHop")
                    next_hop_port = route_info.get("next_hop_port") or parsed.get("NextHopPort")
                # resolve next_hop_port if only name given
                if not next_hop_port and next_hop:
                    next_hop_port = self.name_to_port.get(next_hop)

                if dest and next_hop_port:
                    try:
                        nh = int(next_hop_port)
                        # Determine hop_count from the returned path (prefer parsed Path, fallback to RoutingInfoJson.path)
                        hop_count = 1
                        try:
                            p = parsed.get("Path")
                            if isinstance(p, list) and p:
                                # hops = number of links = nodes_in_path - 1
                                hop_count = max(1, len(p) - 1)
                            else:
                                ri = parsed.get("RoutingInfoJson")
                                if isinstance(ri, dict):
                                    ri_path = ri.get("path")
                                    if isinstance(ri_path, list):
                                        hop_count = max(1, len(ri_path) - 1)
                                    elif isinstance(ri_path, str):
                                        parts = [x.strip() for x in ri_path.split(",") if x.strip()]
                                        hop_count = max(1, len(parts) - 1)
                        except Exception:
                            hop_count = 1
                        # store FIB so future forwarding uses it (use computed hop_count)
                        self.add_fib(dest, nh, exp_time=5000, hop_count=hop_count)
                        print(f"[{self.name}] Stored FIB entry for {dest} -> next hop {nh}")
                        self.log(f"[{self.name}] Stored FIB entry for {dest} -> next hop {nh}")

                        # Mark buffered real-interests for this destination as resolved and set next_hop
                        with self.buffer_lock:
                            forwarded_local = []
                            for entry in list(self.buffer):
                                if entry.get("destination") == dest and entry.get("status") != "resolved":
                                    try:
                                        # parse original buffered packet to preserve origin and seq
                                        parsed_pkt = parse_interest_packet(entry["packet"])
                                        seq = parsed_pkt.get("SequenceNumber")
                                        flags = parsed_pkt.get("Flags", 0x0)
                                        origin_node = parsed_pkt.get("OriginNode", self.name)
                                        # Build REAL_INTEREST packet (data_flag=True) preserving original origin
                                        real_pkt = create_interest_packet(seq, dest, flags, origin_node=origin_node, data_flag=True)
                                        entry["packet"] = real_pkt
                                    except Exception:
                                        # If parsing fails, leave packet as-is
                                        pass
                                    entry["next_hop"] = nh
                                    entry["status"] = "resolved"
                                    entry["timestamp_resolved"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                                    self.log(f"[{self.name}] Marked buffered entry for {dest} resolved -> next_hop {nh}")
                                    print(f"[{self.name}] Marked buffered entry for {dest} resolved -> next_hop {nh}")
                                    forwarded_local.append(entry)
                                    print("hello")
                    except Exception as e:
                        print(f"[{self.name}] Error storing FIB from NS reply: {e}")
                else:
                    print(f"[{self.name}] Route reply missing dest/next_hop info: route_info={route_info}")
                    self.log(f"[{self.name}] Route reply missing dest/next_hop info: route_info={route_info}")

                # NEW: After processing the route, send ROUTE_ACK to any ack_only origins for this destination
                # (e.g., the router that sent the ENCAP packet expecting an ACK upon route resolution)
                pending_acks = self.ns_query_table.get(dest_name, [])
                ack_only_ports = [entry.get("port") for entry in pending_acks if entry.get("ack_only")]
                if ack_only_ports:
                    for port in list(set(ack_only_ports)):  # Deduplicate ports
                        try:
                            #ack_pkt = create_route_ack_packet(parsed.get("SequenceNumber", 0), dest_name)
                            self.sock.sendto(packet, ("127.0.0.1", int(port)))
                            self.log(f"[{self.name}] Sent ROUTE_ACK for {dest_name} to ENCAP origin port {port} (ack_only)")
                        except Exception as e:
                            self.log(f"[{self.name}] Error sending ROUTE_ACK to ENCAP origin port {port}: {e}")
                    # Clear the ack_only entries after sending
                    self.ns_query_table[dest_name] = [entry for entry in pending_acks if not entry.get("ack_only")]
                    if not self.ns_query_table[dest_name]:
                        del self.ns_query_table[dest_name]

                # Also update FIB entry for the route packet name (metadata)
                # Instead of using the sender's port (addr[1]) which can point back toward the origin
                # (causing ping-pong), derive the correct next-hop for reaching the destination
                # from the returned path. If this node appears in the path, set the FIB entry to
                # the next node after this node (toward the destination).
                try:
                    path_list = pkt_obj.path or parsed.get("Path") or []
                    if isinstance(path_list, str):
                        path_list = [p.strip() for p in path_list.split(",") if p.strip()]
                    if path_list and self.name in path_list:
                        idx = path_list.index(self.name)
                        if idx < len(path_list) - 1:
                            next_hop_name = path_list[idx + 1]
                            # resolve port for next_hop_name
                            next_hop_port = self.name_to_port.get(next_hop_name)
                            if next_hop_port is None:
                                fib_entry = self.fib.get(next_hop_name)
                                if fib_entry:
                                    next_hop_port = fib_entry.get("NextHops")
                            if next_hop_port:
                                self.add_fib(pkt_obj.name, int(next_hop_port), exp_time=5000, hop_count=len(path_list) - idx - 1)
                    else:
                        # fallback: if node not in path, avoid installing a route that points back
                        # to the sender. Only install if we can resolve a sensible next-hop.
                        possible_next = None
                        # try to resolve the declared next_hop in the payload if present
                        payload_json = parsed.get("RoutingInfoJson") or {}
                        declared_next = payload_json.get("next_hop") if isinstance(payload_json, dict) else None
                        if declared_next:
                            possible_next = self.name_to_port.get(declared_next) or (self.fib.get(declared_next) or {}).get("NextHops")
                        if possible_next:
                            self.add_fib(pkt_obj.name, int(possible_next), exp_time=5000, hop_count=len(path_list))
                except Exception as e:
                    # If anything fails, fall back to not installing a bad FIB entry.
                    self.log(f"[{self.name}] Failed to install FIB from ROUTE META: {e}")
                return pkt_obj
        
            else:
                path_to_origin = parsed.get("PathToOrigin")
                if path_to_origin and isinstance(path_to_origin, list):
                    normalized_p2o = [p.strip() for p in path_to_origin if isinstance(p, str)]
                    if self.name in normalized_p2o:
                        # If NS included the next hop port for us, forward immediately.
                        explicit_nhp = None
                        if isinstance(route_info, dict):
                            explicit_nhp = route_info.get("next_hop_port")
                        if explicit_nhp is not None:
                            try:
                                nhp_int = int(explicit_nhp)
                                self.sock.sendto(packet, ("127.0.0.1", nhp_int))
                                self.log(f"[{self.name}] Forwarded ROUTE DATA (explicit next_hop_port={nhp_int}) along path_to_origin")
                                return pkt_obj
                            except Exception as e:
                                self.log(f"[{self.name}] Failed explicit next_hop_port forward: {e}")
                        # Fallback: existing name-based hop resolution
                        idx = normalized_p2o.index(self.name)
                        for j in range(idx + 1, len(normalized_p2o)):
                            next_hop_name = normalized_p2o[j]
                            next_port = _resolve_port_by_name(next_hop_name)
                            if next_port is not None:
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", next_port))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA along path_to_origin to {next_hop_name} (port {next_port})")
                                    return pkt_obj
                                except Exception as e:
                                    self.log(f"[{self.name}] Error forwarding ROUTE DATA to {next_hop_name} at port {next_port}: {e}")
                                    # try next candidate hop
                        # If none resolvable, fall through to existing logic

                # If not for this node:
                # 1) first try to forward the ROUTE reply back to any interface(s) that previously
                #    sent an NS QUERY for this destination (ns_query_table).
                # 2) fallback to path-based forwarding / PIT / direct-origin as before.
                #
                # This ensures intermediate routers that forwarded a data=False query can receive
                # the reply and continue the recursive resolution.
                dest_name = parsed.get("Name")
                pending = self.ns_query_table.get(dest_name, [])
                if pending:
                    # pending is list of dicts { "port": <int>, "ack_only": <bool> }
                    for entry in list(pending):
                        try:
                            p = int(entry.get("port"))
                            if entry.get("ack_only"):
                                # The interface who asked us used ack-only registration (e.g. ENCAP origin).
                                # They still need the full ROUTE_DATA so they can continue resolution. Send full packet;
                                # if that fails, fall back to sending a lightweight ROUTE_ACK.
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", p))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA for {dest_name} to NS-query iface port {p} (ack_only -> sent full ROUTE_DATA)")
                                except Exception as e:
                                    # fallback: send lightweight ack only
                                    try:
                                        ack_pkt = create_route_ack_packet(parsed.get("SequenceNumber", 0), dest_name)
                                        self.sock.sendto(ack_pkt, ("127.0.0.1", p))
                                        self.log(f"[{self.name}] Sent ROUTE_ACK for {dest_name} to NS-query iface port {p} (ack_only, fallback due to send error: {e})")
                                    except Exception as e2:
                                        self.log(f"[{self.name}] Failed to send ROUTE_DATA or ROUTE_ACK to port {p}: {e2}")
                            else:
                                # original behaviour: forward full ROUTE_DATA
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", p))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA for {dest_name} to NS-query iface port {p}")
                                    print(f"[{self.name}] Forwarded ROUTE DATA for {dest_name} to NS-query iface port {p}")
                                except Exception as e:
                                    self.log(f"[{self.name}] Error forwarding ROUTE response to NS-query iface {entry}: {e}")
                        except Exception as e:
                            self.log(f"[{self.name}] Error forwarding ROUTE response to NS-query iface {entry}: {e}")
                    # clear recorded pending query interfaces for this destination
                    try:
                        del self.ns_query_table[dest_name]
                    except KeyError:
                        pass
                    return pkt_obj

                # If not for this node, try to forward the ROUTING_DATA back along the path
                self.log(f"[{self.name}] ROUTING_DATA origin_name mismatch ({origin_name}), attempting path-based forwarding.")
                path = parsed.get("Path") or (parsed.get("RoutingInfoJson") or {}).get("path") or []
                try:
                    # ensure path is a list of strings
                    if isinstance(path, str):
                        path = path.split(",")
                except Exception:
                    path = []

                forwarded = False
                if path and isinstance(path, list):
                    # Normalize path entries
                    normalized = [p.strip() for p in path if isinstance(p, str)]
                    if self.name in normalized:
                        idx = normalized.index(self.name)
                        if idx > 0:
                            # previous hop on path is toward the origin
                            prev_hop_name = normalized[idx - 1]
                            # try to resolve prev_hop_name to a port
                            prev_port = None
                            prev_port = self.name_to_port.get(prev_hop_name)
                            if prev_port is None:
                                fib_entry = self.fib.get(prev_hop_name)
                                if fib_entry:
                                    prev_port = fib_entry.get("NextHops")
                            if prev_port is not None:
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", int(prev_port)))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA for {parsed.get('Name')} to previous hop {prev_hop_name} (port {prev_port})")
                                    forwarded = True
                                except Exception as e:
                                    self.log(f"[{self.name}] Error forwarding ROUTE DATA to previous hop {prev_hop_name} at port {prev_port}: {e}")
                    # if this node is not in path or couldn't forward via path, fallthrough to other methods

                if not forwarded:
                    # Try to forward directly to origin if we know its port
                    if origin_name:
                        origin_port = self.name_to_port.get(origin_name)

                        # If exact match failed, try relaxed/alias match (prefix-style).
                        if origin_port is None:
                            for known_name, known_port in list(self.name_to_port.items()):
                                try:
                                    # Accept if origin_name starts with known_name (known is prefix),
                                    # or known_name starts with origin_name (origin is a prefix of known).
                                    # This covers cases like "/DLSU/Andrew" vs "/DLSU/Andrew/PC1".
                                    if (isinstance(known_name, str) and isinstance(origin_name, str) and
                                            (origin_name.startswith(known_name) or known_name.startswith(origin_name))):
                                        origin_port = known_port
                                        break
                                except Exception:
                                    continue

                        if origin_port:
                            try:
                                self.sock.sendto(packet, ("127.0.0.1", int(origin_port)))
                                self.log(f"[{self.name}] Forwarded ROUTE DATA directly to origin {origin_name} at port {origin_port}")
                                return pkt_obj
                            except Exception as e:
                                self.log(f"[{self.name}] Failed direct forward to origin {origin_name}: {e}")

                    # Fallback: forward to any PIT interfaces (existing behaviour)
                    self.log(f"[{self.name}] Falling back to PIT forwarding for ROUTE DATA.")
                    for pit_entry in self.pit.values():
                        if isinstance(pit_entry, list):
                            for port in pit_entry:
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", int(port)))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA to PIT port {port}")
                                except Exception as e:
                                    self.log(f"[{self.name}] Error forwarding ROUTE DATA to PIT port {port}: {e}")
                return pkt_obj

        elif packet_type == ERROR:
            parsed = parse_error_packet(packet)
            origin_name = parsed.get("OriginNode")
            err_code = parsed.get("ErrorCode")
            err_name = parsed.get("Name")
            seq = parsed.get("SequenceNumber")
            # Map error code to human message
            if err_code == FORMAT_ERROR:
                err_text = "Format Error"
            elif err_code == NAME_ERROR:
                err_text = "Name Error"
            elif err_code == NO_DATA_ERROR:
                err_text = "Data Not Found"
            elif err_code == DROPPED_ERROR:
                err_text = "Packet Dropped"
            else:
                err_text = f"Unknown Error 0x{err_code:02x}"

            print(f"[{self.name}] Received ERROR ({err_text}) for '{err_name}' seq={seq} origin={origin_name} at {timestamp}")
            self.log(f"[{self.name}] Received ERROR ({err_text}) for '{err_name}' seq={seq} origin={origin_name} at {timestamp}")

            # Forwarding logic for NAME_ERROR: follow the same path as ROUTING_DATA
            if err_code == FORMAT_ERROR:
                print(f"[{self.name}] FORMAT_ERROR received for '{err_name}' seq={seq} at {timestamp}")
                self.log(f"[{self.name}] FORMAT_ERROR received for '{err_name}' seq={seq} at {timestamp}")
            elif err_code == NAME_ERROR:
                # Try to forward back along the path if available
                dest_name = parsed.get("Name")
                pending_ifaces = self.ns_query_table.get(dest_name, [])
                if pending_ifaces:
                    for p in list(pending_ifaces):
                        try:
                            print(f"[{self.name}] Forwarded NAME_ERROR for {dest_name} to NS-query iface port {p}")
                            self.log(f"[{self.name}] Forwarded NAME_ERROR for {dest_name} to NS-query iface port {p}")
                            self.sock.sendto(packet, ("127.0.0.1", int(p)))
                        except Exception as e:
                            #print(f"[{self.name}] Error forwarding NAME_ERROR to NS-query iface {p}: {e}")
                            self.log(f"[{self.name}] Error forwarding NAME_ERROR to NS-query iface {p}: {e}")
                    # clear recorded pending query interfaces for this destination
                    try:
                        del self.ns_query_table[dest_name]
                    except KeyError:
                        pass
            elif err_code == NO_DATA_ERROR or err_code == DROPPED_ERROR:
                #error_pkt = create_error_packet(parsed["SequenceNumber"], parsed["Name"], err_code, origin_node=origin_name)
                
                if origin_name != self.name:
                    pit_ifaces = self.pit.get(parsed["Name"], [])
                    name = parsed["Name"]
                    if pit_ifaces:
                        for iface_port in list(pit_ifaces):
                            self.sock.sendto(packet, ("127.0.0.1", int(iface_port)))

                            if err_code == DROPPED_ERROR:
                                self.log(f"[{self.name}] Forwarded ERROR (Packet Dropped) for '{name}' to PIT iface {iface_port}")
                                print(f"[{self.name}] Forwarded ERROR (Packet Dropped) for '{name}' to PIT iface {iface_port}")
                            elif err_code == NO_DATA_ERROR:
                                self.log(f"[{self.name}] Forwarded ERROR (Data Not Found) for '{name}' to PIT iface {iface_port}")
                                print(f"[{self.name}] Forwarded ERROR (Data Not Found) for '{name}' to PIT iface {iface_port}")
                            else:
                                self.log(f"[{self.name}] Forwarded ERROR for '{name}' to PIT iface {iface_port}")
                                print(f"[{self.name}] Forwarded ERROR for '{name}' to PIT iface {iface_port}")
                        self.remove_pit(parsed["Name"])
                    return
                else:
                    print(f"[{self.name}] RECEIVED ERROR: {err_text} for '{err_name}' seq={seq} at {timestamp}")
            return None
        else:
            print(f"[{self.name}] Unknown packet type {packet_type} from {addr} at {timestamp}")
            self.log(f"[{self.name}] Unknown packet type {packet_type} from {addr} at {timestamp}")
    
    def get_neighbors(self):
        return self.neighbor_table

    def _is_ns_port(self, port):
        """Return True if 'port' belongs to a known NameServer (avoid registering NS ports in ns_query_table)."""
        try:
            p = int(port)
        except Exception:
            return False
        for nm, nm_port in list(self.name_to_port.items()):
            try:
                if "NameServer" in nm and int(nm_port) == p:
                    return True
            except Exception:
                continue
        return False

    def remove_stale_neighbors(self, timeout=30):
        now = datetime.now()
        stale = []
        for addr, ts in self.neighbor_table.items():
            last_seen = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
            if (now - last_seen).total_seconds() > timeout:
                stale.append(addr)
        for addr in stale:
            del self.neighbor_table[addr]
            print(f"[{self.name}] Removed stale neighbor {addr}")
            self.log(f"[{self.name}] Removed stale neighbor {addr}")
    
    def stop(self):
        self.running = False
        try:
            self.sock.sendto(b"", (self.host, self.port))
        except Exception:
            pass
        time.sleep(0.1)
        self.sock.close()

    def remove_fib(self, name):
        if name in self.fib:
            del self.fib[name]

    def add_cs(self, name, data):
        self.cs[name] = data

    def remove_cs(self, name):
        if name in self.cs:
            del self.cs[name]

    def add_pit(self, name, interface):
        self.pit_interfaces.append(interface)
        self.pit[name] = (list(self.pit_interfaces))

    def remove_pit(self, name, interface=None):
        if name in self.pit:
            if interface is None:
                del self.pit[name]
                print(f"[{self.name}] Removed {name} from PIT.")
                self.log(f"[{self.name}] Removed {name} from PIT.")
            else:
                if interface in self.pit[name]:
                    self.pit[name].remove(interface)
                    print(f"[{self.name}] Removed interface {interface} from PIT entry {name}.")
                    self.log(f"[{self.name}] Removed interface {interface} from PIT entry {name}.")
                if not self.pit[name]:
                    del self.pit[name]
                    print(f"[{self.name}] Removed {name} from PIT (no interfaces left).")
                    self.log(f"[{self.name}] Removed {name} from PIT (no interfaces left).")

    def levenshtein_distance(self, s1, s2):
        # Exclude '/' from both strings before comparison
        s1 = s1.replace('/', '')
        s2 = s2.replace('/', '')
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def check_tables(self, name):
        # 1. CS: Exact match or Levenshtein <= 3
        for key in self.cs.keys():
            if name == key:
                return "CS", self.cs[key]
        for key in self.cs.keys():
            score = self.levenshtein_distance(name, key)
            if score <= 3:
                return "CS", self.cs[key]

        # 2. PIT: Exact match only
        for key in self.pit.keys():
            if name == key:
                return "PIT", self.pit[key]

        # 3. FIB: FIRST try exact match on the full name
        if name in self.fib:
            return "FIB", self.fib[name]

        # 4. FIB: Match interest name with FIB entry except last level (data name)
        def strip_last_level(path):
            if not path:
                return path
            segments = path.strip('/').split('/')
            if len(segments) > 1:
                return '/' + '/'.join(segments[:-1])
            return path

        fib_interest = strip_last_level(name)

        # prefer an exact parent-key in the FIB (e.g. '/DLSU') but only if that entry came from NS
        if fib_interest in self.fib and self.fib[fib_interest].get("Source") == "NS":
            return "FIB", self.fib[fib_interest]

        # fallback: only accept parent/fuzzy matches that were installed by the NameServer
        best_key = None
        for key, entry in self.fib.items():
            # consider keys that represent parent namespaces (strip last level of the FIB key)
            fib_key_parent = strip_last_level(key)
            if fib_key_parent == fib_interest and entry.get("Source") == "NS":
                best_key = key
                break

        if best_key is not None:
            return "FIB", self.fib[best_key]

        return None, None
        
    def add_neighbor(self, addr, port):
        key = (addr, port)
        if key not in self.neighbor_table:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            self.neighbor_table[key] = timestamp
            print(f"[{self.name}] Added neighbor {key} to neighbor_table.")
            self.log(f"[{self.name}] Added neighbor {key} to neighbor_table.")
        else:
            print(f"[{self.name}] Neighbor {key} already exists in neighbor_table.")
            self.log(f"[{self.name}] Neighbor {key} already exists in neighbor_table.")

    def send_ns_update_to_domain_neighbors(self, sender_name, sender_domains, ns_update_packet, exclude_port=None):
        """
        Send NS UPDATE packet to all neighbors whose domain matches sender_domains.
        exclude_port: port to exclude from sending (e.g., sender's port)
        """
        for neighbor_name in self.neighbor_table.keys():
            neighbor_domains = get_domains_from_name(neighbor_name)
            for n in neighbor_domains:
                #print(f"[{self.name}] Checking neighbor domain for {neighbor_name}: {n}")
                for domain in sender_domains:
                    if domain == n:
                        neighbor_port = self.name_to_port.get(neighbor_name)
                        if neighbor_port and (exclude_port is None or neighbor_port != exclude_port):
                            send_addr = (self.host, neighbor_port)
                            self.sock.sendto(ns_update_packet, send_addr)
                            #print(f"[{self.name}] Sent NS UPDATE to {neighbor_name} at {send_addr}")