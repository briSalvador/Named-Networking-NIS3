import socket
import threading
import struct
import time
import json
from DataPacket import DataPacket
from RouteDataPacket import RouteDataPacket
from InterestPacket import InterestPacket
from Packet import Packet
from datetime import datetime
from collections import deque

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

# Flag Masks (lower 4 bits)
ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

FRAGMENT_SIZE = 1500

# TODO (As of Sep 30): 
# FIB: Add hop count for FIB entries so that new routes are compared with existing ones and replaced
# if new route is shorter.

def create_interest_packet(seq_num, name, flags=0x0, origin_node="", data_flag=False):
    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)
    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)
    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes)
    data_flag_byte = b'\x01' if data_flag else b'\x00'
    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = header + name_bytes + struct.pack("!B", origin_length) + origin_bytes + data_flag_byte
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
    }

def parse_route_data_packet(packet):
    """
    ROUTING_DATA format (matches NameServer.create_route_data_packet):
    header: !BBBB  => packet_type_flags, seq_num, payload_size, name_length
    then name_bytes (name_length) then payload_bytes (payload_size)
    payload is usually JSON (dict) when created by the NameServer.
    """
    packet_type_flags, seq_num, payload_size, name_length = struct.unpack("!BBBB", packet[:4])
    name_start = 4
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")
    payload_start = name_end
    payload_end = payload_start + payload_size
    payload_bytes = packet[payload_start:payload_end]
    payload_text = payload_bytes.decode("utf-8", errors="ignore")
    payload = None
    try:
        payload = json.loads(payload_text)
    except Exception:
        # fallback: keep raw text
        payload = payload_text
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF
    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "Payload": payload,
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

def parse_route_data_packet(packet):
    if len(packet) < 4:
        raise ValueError("Packet too short to parse route data header")
    packet_type_flags, seq_num, info_size, name_length = struct.unpack("!BBBB", packet[:4])
    if len(packet) < 4 + name_length + info_size:
        raise ValueError("Packet too short for declared name/routing info lengths")
    name = packet[4:4+name_length].decode("utf-8")
    routing_info = packet[4+name_length:4+name_length+info_size]

    try:
        routing_info_decoded = routing_info.decode("utf-8")
    except Exception:
        routing_info_decoded = routing_info

    # Try to parse as JSON if possible
    try:
        routing_info_json = json.loads(routing_info_decoded)
    except Exception:
        routing_info_json = None

    # Extract all relevant fields from the new route data packet format
    path = []
    origin_name = None
    dest = None
    next_hop = None
    next_hop_port = None
    if isinstance(routing_info_json, dict):
        path = routing_info_json.get("path", [])
        origin_name = routing_info_json.get("origin_name")
        dest = routing_info_json.get("dest")
        next_hop = routing_info_json.get("next_hop")
        next_hop_port = routing_info_json.get("next_hop_port")
    elif isinstance(routing_info_decoded, str) and "," in routing_info_decoded:
        path = routing_info_decoded.split(",")
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "InfoSize": info_size,
        "NameLength": name_length,
        "Name": name,
        "Path": path,
        "OriginName": origin_name,
        "Dest": dest,
        "NextHop": next_hop,
        "NextHopPort": next_hop_port,
        "RoutingInfo": routing_info_decoded,
        "RawRoutingInfo": routing_info,
        "RoutingInfoJson": routing_info_json
    }


def create_route_data_packet(seq_num, name, routing_info, flags=0x0):
    """
    Create a ROUTING_DATA packet. routing_info can be a list (path) or a string.
    Packet format: !BBBB | name_bytes | routing_info_bytes
      packet_type_flags (1 byte), seq_num (1), info_size (1), name_length (1)
    """
    packet_type = ROUTING_DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)
    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF

    if isinstance(routing_info, list):
        routing_info_bytes = ",".join(routing_info).encode("utf-8")
    elif isinstance(routing_info, str):
        routing_info_bytes = routing_info.encode("utf-8")
    else:
        routing_info_bytes = bytes(routing_info)

    info_size = len(routing_info_bytes) & 0xFF
    header = struct.pack("!BBBB", packet_type_flags, seq_num, info_size, name_length)
    return header + name_bytes + routing_info_bytes

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

    def __init__(self, name, host="127.0.0.1", port=0, broadcast_port=9999):
        self.name = name
        self.domains = get_domains_from_name(name)
        self.host = host
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
        Process an incoming ROUTING_DATA packet:
        - If the ROUTE is for this node (origin_name == self.name) -> update FIB and forward buffered
          'real' interest packets for that destination to the discovered next hop.
        - Otherwise, forward the ROUTING_DATA to interfaces recorded in the PIT for the destination.
        - Fallback: if no PIT entry, attempt direct send to origin_name's port (if known).
        """
        parsed = parse_route_data_packet(packet)
        payload = parsed.get("Payload")
        dest_name = parsed.get("Name")
        origin_name = None
        next_hop_name = None

        if isinstance(payload, dict):
            origin_name = payload.get("origin_name") or payload.get("origin")
            next_hop_name = payload.get("next_hop") or payload.get("nextHop") or payload.get("next")
            # sometimes payload might include explicit destination
            dest_name = payload.get("destination") or dest_name
        else:
            # try simple textual parse: "origin:... next_hop:..."
            text = payload if isinstance(payload, str) else ""
            # crude parsing in case NS used a non-json payload
            try:
                parts = text.split()
                for p in parts:
                    if p.startswith("origin="):
                        origin_name = p.split("=", 1)[1]
                    if p.startswith("next_hop=") or p.startswith("nextHop="):
                        next_hop_name = p.split("=", 1)[1]
            except Exception:
                pass

        self.log(f"[{self.name}] Received ROUTE DATA from {addr} payload={payload}")

        # Ensure path is normalized to a list of node-names
        path_field = parsed.get("Path", [])
        if isinstance(path_field, str):
            path = [p.strip() for p in path_field.split(",") if p.strip()]
        elif isinstance(path_field, list):
            path = path_field
        else:
            path = []

        # If this node appears in the returned path, install a FIB entry pointing
        # to the next hop in that path (toward the destination). This prevents
        # installing FIBs that point back to the sender port and avoids ping-pong.
        try:
            if path and self.name in path:
                idx = path.index(self.name)
                if idx < len(path) - 1:
                    next_node_name = path[idx + 1]
                    # Resolve port for next_node_name
                    next_port = None
                    if next_node_name in self.name_to_port:
                        try:
                            next_port = int(self.name_to_port[next_node_name])
                        except Exception:
                            next_port = None
                    if next_port is None:
                        fib_entry = self.fib.get(next_node_name)
                        if fib_entry:
                            try:
                                next_port = int(fib_entry["NextHops"])
                            except Exception:
                                next_port = None
                    if next_port:
                        remaining_hops = len(path) - idx - 1
                        # IMPORTANT: mark this FIB as coming from the NameServer so it
                        # can be used for parent/fuzzy matching by other nodes.
                        self.add_fib(dest_name, next_port, exp_time=5000, hop_count=remaining_hops, source="NS")
                        self.log(f"[{self.name}] Installed FIB for {dest_name} -> next hop {next_node_name} (port {next_port}), remaining_hops={remaining_hops}")
        except Exception as e:
            self.log(f"[{self.name}] Error installing FIB from ROUTE path: {e}")

        # If this ROUTING_DATA is for this node (we were the origin of the original NS query)
        if origin_name == self.name:
            # Update FIB for the destination using the provided next_hop_name (if resolvable)
            if next_hop_name:
                next_port = self.name_to_port.get(next_hop_name)
                if next_port:
                    self.fib[dest_name] = {"NextHops": str(next_port)}
                    self.log(f"[{self.name}] Updated FIB: {dest_name} -> {next_hop_name} (port {next_port})")
                else:
                    self.log(f"[{self.name}] ROUTE contains next_hop {next_hop_name} but no port known locally")

            # Forward any buffered "real" interest packets for this destination to the discovered next hop
            forwarded = []
            with getattr(self, "buffer_lock", threading.Lock()):
                if hasattr(self, "buffer"):
                    for entry in list(self.buffer):
                        if entry.get("destination") == dest_name:
                            target_port = None
                            # prefer explicit FIB entry we just set
                            if dest_name in self.fib:
                                target_port = int(self.fib[dest_name]["NextHops"])
                            elif next_hop_name:
                                target_port = self.name_to_port.get(next_hop_name)
                            if target_port:
                                try:
                                    self.sock.sendto(entry["packet"], ("127.0.0.1", target_port))
                                    forwarded.append(entry)
                                    self.log(f"[{self.name}] Forwarded buffered real interest for {dest_name} to port {target_port}")
                                except Exception as e:
                                    self.log(f"[{self.name}] Error sending buffered interest to port {target_port}: {e}")
            # remove forwarded entries from buffer
            if forwarded:
                with getattr(self, "buffer_lock", threading.Lock()):
                    for e in forwarded:
                        try:
                            self.buffer.remove(e)
                        except ValueError:
                            pass
            return

        # Not for this node: forward to PIT interfaces for the destination
        pit_ifaces = self.pit.get(dest_name, [])
        if pit_ifaces:
            for iface_port in list(pit_ifaces):
                try:
                    self.sock.sendto(packet, ("127.0.0.1", int(iface_port)))
                    self.log(f"[{self.name}] Forwarded ROUTE DATA for {dest_name} to PIT iface port {iface_port}")
                except Exception as e:
                    self.log(f"[{self.name}] Error forwarding ROUTE DATA to PIT iface {iface_port}: {e}")
            return

        # No PIT entries — try to forward to the origin directly if we know its port
        if origin_name:
            origin_port = self.name_to_port.get(origin_name)
            if origin_port:
                try:
                    self.sock.sendto(packet, ("127.0.0.1", int(origin_port)))
                    self.log(f"[{self.name}] No PIT for {dest_name}; forwarded ROUTE DATA directly to origin {origin_name} at port {origin_port}")
                    return
                except Exception as e:
                    self.log(f"[{self.name}] Failed to forward ROUTE DATA to origin {origin_name}: {e}")

        # Nothing to do - drop and log
        self.log(f"[{self.name}] DROPPED ROUTE DATA for {dest_name}: no PIT and unknown origin {origin_name}")

        try:
            parsed = parse_route_data_packet(packet)
            # Basic route fields
            dest = parsed.get("Dest")
            next_hop = parsed.get("NextHop")
            next_hop_port = parsed.get("NextHopPort")
            self.log(f"ROUTE_RX from {addr} name={parsed.get('Name')} dest={dest} next_hop={next_hop} next_hop_port={next_hop_port}")

            # Check resolvability: name_to_port maps node_name -> port
            resolvable = False
            reason = []
            if next_hop_port is not None:
                try:
                    nhp_int = int(next_hop_port)
                    if nhp_int in set(self.name_to_port.values()):
                        resolvable = True
                        reason.append("next_hop_port found in name_to_port.values()")
                except Exception:
                    reason.append("next_hop_port not int")
            if next_hop:
                if next_hop in self.name_to_port:
                    resolvable = True
                    reason.append("next_hop found in name_to_port keys")
            self.log(f"ROUTE_DEBUG resolvable={resolvable} reason={reason} name_to_port_keys={list(self.name_to_port.keys())} name_to_port_values={list(self.name_to_port.values())[:10]}")

            # Dump buffer destinations for comparison
            try:
                buf_snapshot = list(self.buffer)
                self.log(f"BUFFER_SNAPSHOT count={len(buf_snapshot)}")
                for i, entry in enumerate(buf_snapshot):
                    # normalize possible keys
                    entry_dest = entry.get("dest") or entry.get("Name") or entry.get("destination") or entry.get("Destination")
                    entry_status = entry.get("status")
                    entry_origin = entry.get("origin") or entry.get("OriginNode")
                    self.log(f"BUFFER[{i}] dest={entry_dest} status={entry_status} origin={entry_origin}")
                    # exact-match check against route dest
                    if dest is not None and entry_dest == dest:
                        self.log(f"BUFFER_MATCH found index={i} entry_dest==route_dest ({dest})")
                        # (existing code should mark resolved / forward — ensure it uses exact match)
                # continue normal handling...
            except Exception as e:
                self.log(f"BUFFER_DUMP_EXC: {e}")
        except Exception as e:
            self.log(f"_handle_route_data EXC: {e}")

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
                self.receive_packet(data, addr)
                # with self.buffer_lock:
                    # Add raw packet to buffer first
                    #self.buffer.append((data, addr))
                print(f"[{self.name}] Received packet from {addr}, added to buffer (size={len(self.buffer)})")
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
        pkt = create_interest_packet(seq_num, name, flags, origin_node=self.name, data_flag=data_flag)
        self.sock.sendto(pkt, target)
        print(f"[{self.name}] Sent INTEREST packet to {target} (data_flag={data_flag})")
        self.log(f"[{self.name}] Sent INTEREST packet to {target} (data_flag={data_flag})")
        self.add_to_buffer(pkt, target, reason="Originated Interest")
        return pkt

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
        # interface is the next hop port (int)
        entry = {
            "NextHops": interface,
            "ExpirationTime": exp_time,
            "HopCount": hop_count,
            "Source": source
        }
        if name not in self.fib:
            self.fib[name] = entry
        elif name in self.fib and hop_count < self.fib[name]["HopCount"]:
            self.fib[name] = entry

        self.log(f"[{self.name}] FIB updated: {self.fib}")

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
                        update_pkt = create_neighbor_update_packet(neighbor_name, self.name)
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

        if packet_type == INTEREST:
            parsed = parse_interest_packet(packet)
            is_real_interest = parsed["DataFlag"]
            origin_node = parsed["OriginNode"]

            # --- Encapsulation handling: INTERESTs created by NameServer use the form:
            # "ENCAP:<border_alias>|<original_name>"
            # Nodes must not send encapsulated queries to their own NameServer; instead
            # forward encapsulated packet toward the border alias. When the border node
            # itself receives the ENCAP packet it strips it and continues normal processing.
            enc_name = None
            enc_border = None
            if isinstance(parsed.get("Name"), str) and parsed["Name"].startswith("ENCAP:"):
                try:
                    rest = parsed["Name"][6:]
                    enc_border, enc_name = rest.split("|", 1)
                    enc_border = enc_border.strip()
                    enc_name = enc_name.strip()
                except Exception:
                    enc_border = None
                    enc_name = None

            if enc_border:
                # If this node is the border (one of its aliases), strip encapsulation and
                # treat the Interest as if its Name is the original target.
                if enc_border in self.name.split():
                    parsed["Name"] = enc_name
                    packet = create_interest_packet(parsed["SequenceNumber"], enc_name, parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=False)
                    is_real_interest = False
                   # continue processing below
                else:
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
                            self.sock.sendto(packet, ("127.0.0.1", target_port))
                            self.log(f"[{self.name}] Forwarded ENCAP packet for {enc_name} toward border {enc_border} at port {target_port}")
                            print(f"[{self.name}] Forwarded ENCAP packet for {enc_name} toward border {enc_border} at port {target_port}")
                            return
                        except Exception as e:
                            self.log(f"[{self.name}] Error forwarding ENCAP to {enc_border}:{target_port} - {e}")

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
            # --- end encapsulation handling


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
                # Return the parent node for a given full name.
                # Examples:
                #   "/DLSU/hello.txt" -> "/DLSU"
                #   "/DLSU/Miguel/cam1/hello.txt" -> "/DLSU/Miguel/cam1"
                if not name:
                    return name
                s = name.strip('/')
                parts = s.split('/')
                if len(parts) == 0:
                    return name
                if len(parts) == 1:
                    return '/' + parts[0]
                return '/' + '/'.join(parts[:-1])
            
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
            node_name = get_node_name(parsed["Name"])
            neighbor_port = self.name_to_port.get(node_name)
            # Allow direct neighbor forwarding only when:
            #  - this node is the originator (it created the query),
            #  OR
            #  - this is a REAL_INTEREST and this node either already asked its NameServer
            #    for this destination (so it attempted local resolution) OR it already has
            #    a FIB entry for the destination.
            allow_direct = False
            if neighbor_port is not None:
                if origin_node == self.name:
                    allow_direct = True
                elif is_real_interest:
                    # permit only if we've previously queried NS for this dest or we already have a FIB
                    if parsed["Name"] in self.fib or _has_asked_ns(parsed["Name"]):
                        allow_direct = True

            if neighbor_port is not None and allow_direct:
                role = "originator" if origin_node == self.name else "in-transit(resolved)"
                print(f"[{self.name}] ({role}) Destination {parsed['Name']} is a direct neighbor node {node_name} at port {neighbor_port}, forwarding directly.")
                self.log(f"[{self.name}] ({role}) Destination {parsed['Name']} is a direct neighbor node {node_name} at port {neighbor_port}, forwarding directly.")
                pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=True)
                self.sock.sendto(pkt, ("127.0.0.1", neighbor_port))
                return
            # Otherwise do not forward directly here; let the normal NS-query path handle it.

            # If this is a query to the NameServer (data_flag == False)
            if not is_real_interest:
                # If the packet originated here, we already added it to PIT above.
                # Routers that receive data=False should NOT rewrite the origin; they should forward
                # the same packet toward the domain NameServer.
                # Record the incoming interface so we can forward the NS ROUTE reply back here.
                # This fixes the case where an intermediate router (e.g. /DLSU/Henry) forwarded
                # the query to the NameServer but didn't know how to route the NS reply back.
                try:
                    self.ns_query_table.setdefault(parsed["Name"], [])
                    if addr[1] not in self.ns_query_table[parsed["Name"]]:
                        self.ns_query_table[parsed["Name"]].append(addr[1])
                        self.log(f"[{self.name}] Recorded NS query origin iface {addr[1]} for {parsed['Name']}")
                except Exception:
                    pass

                own_domain = self.domains[0] if self.domains else None
                if own_domain:
                    ns_name = f"/{own_domain}/NameServer1"
                    fib_entry = self.fib.get(ns_name)
                    if fib_entry:
                        ns_port = fib_entry["NextHops"]
                        try:
                            # forward unchanged to the name server
                            self.sock.sendto(packet, ("127.0.0.1", int(ns_port)))
                            print(f"[{self.name}] Forwarded NS QUERY for {parsed['Name']} -> {ns_name} (via port {ns_port}) origin={origin_node}")
                            self.log(f"[{self.name}] Forwarded NS QUERY for {parsed['Name']} -> {ns_name} (via port {ns_port}) origin={origin_node}")
                        except Exception as e:
                            print(f"[{self.name}] Error forwarding NS query to {ns_name}: {e}")
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
            # From here: is_real_interest == True (this is the "real" Interest for the file)
            # If we don't have CS or FIB entry, buffer the real interest and ask the NS on behalf of this node.
            if table is None or table == "PIT":
                # Before buffering and creating a NameServer query for a REAL interest,
                # re-check whether destination is a direct neighbor and forward directly if so.
                # Allow direct-forward when this node itself is directly connected to the destination
                # (special-case: node is adjacent to the dest) — this executes only in the pre-NS path.
                if is_real_interest:
                    node_name = get_node_name(parsed["Name"])
                    neighbor_port = self.name_to_port.get(node_name)
                    if neighbor_port is not None:
                        # direct-adjacent: forward straight to neighbor (no NS query needed)
                        print(f"[{self.name}] (pre-NS) Destination {parsed['Name']} is a direct neighbor {node_name} at port {neighbor_port}, forwarding directly (real interest).")
                        self.log(f"[{self.name}] (pre-NS) Destination {parsed['Name']} is a direct neighbor {node_name} at port {neighbor_port}, forwarding directly (real interest).")
                        pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed["OriginNode"], data_flag=True)
                        self.sock.sendto(pkt, ("127.0.0.1", int(neighbor_port)))
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
                    # Always send to own domain's NameServer, regardless of interest's domain
                    own_domain = self.domains[0] if self.domains else None
                    if own_domain:
                        ns_name = f"/{own_domain}/NameServer1"
                        # try FIB entry for that domain's NameServer, or direct mapping if known
                        fib_entry = self.fib.get(ns_name)
                        ns_port = None
                        if fib_entry:
                            ns_port = fib_entry["NextHops"]
                        else:
                            # fallback to known port from HELLOs/UPDATEs
                            ns_port = self.name_to_port.get(ns_name)
                        if ns_port:
                            try:
                                # create a query packet (data=False) where this router is origin
                                query_pkt = create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=self.name, data_flag=False)
                                self.sock.sendto(query_pkt, ("127.0.0.1", int(ns_port)))
                                print(f"[{self.name}] Sent NS QUERY for {parsed['Name']} (origin={self.name}) -> {ns_name} via port {ns_port}")
                                self.log(f"[{self.name}] Sent NS QUERY for {parsed['Name']} (origin={self.name}) -> {ns_name} via port {ns_port}")
                                # mark buffered entries as forwarded to NS (do NOT modify buffered packet origin)
                                with self.buffer_lock:
                                    for entry in self.buffer:
                                        if entry.get("destination") == parsed["Name"]:
                                            entry["forwarded_to_ns"] = True
                            except Exception as e:
                                print(f"[{self.name}] Error forwarding INTEREST query to NS via port {ns_port}: {e}")
                                self.log(f"[{self.name}] Error forwarding INTEREST query to NS via port {ns_port}: {e}")
                        else:
                            print(f"[{self.name}] No route to NameServer {ns_name} (no FIB entry or known port). Will keep buffered.")
                            self.log(f"[{self.name}] No route to NameServer {ns_name} (no FIB entry or known port). Will keep buffered.")
                return  # buffered unknown routes for real interest

            if table == "CS":
                print(f"[{self.name}] Data found in CS for {parsed['Name']}, sending DATA back to {addr}")
                self.log(f"[{self.name}] Data found in CS for {parsed['Name']}, sending DATA back to {addr}")
                self.send_data(
                    seq_num=pkt_obj.seq_num,
                    name=pkt_obj.name,
                    payload=data,
                    flags=ACK_FLAG,
                    target=addr
                )
                self.remove_pit(pkt_obj.name, addr[1])
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
                            pkt = create_data_packet(parsed["SequenceNumber"], name, full_payload, parsed["Flags"], 1, 1)
                            self.sock.sendto(pkt, (self.host, interface))
                            self.log(f"Forwarded reassembled DATA to PIT interface {interface}")
                            self.remove_pit(name, interface)
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
                        pkt = create_data_packet(parsed["SequenceNumber"], name, parsed["Payload"], parsed["Flags"], 1, 1)
                        self.sock.sendto(pkt, (self.host, interface))
                        self.log(f"Forwarded DATA to PIT interface {interface}")
                        self.remove_pit(name, interface)

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

        elif packet_type == UPDATE:
            parsed = parse_update_packet(packet)
            neighbor_name = parsed["Name"]
            self.log(f"[{self.name}] Received UPDATE from {neighbor_name} at {addr} with parsed data: {parsed}")
            #print(f"[{self.name}] Received UPDATE from {neighbor_name} at {addr} with parsed data: {parsed}")
            if parsed["Flags"] == 0x1:
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
                        # store FIB so future forwarding uses it
                        self.add_fib(dest, nh, exp_time=5000, hop_count=1)
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
                                    forwarded_local.append(entry)
                    except Exception as e:
                        print(f"[{self.name}] Error storing FIB from NS reply: {e}")
                else:
                    print(f"[{self.name}] Route reply missing dest/next_hop info: route_info={route_info}")
                    self.log(f"[{self.name}] Route reply missing dest/next_hop info: route_info={route_info}")

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
                # If not for this node:
                # 1) first try to forward the ROUTE reply back to any interface(s) that previously
                #    sent an NS QUERY for this destination (ns_query_table).
                # 2) fallback to path-based forwarding / PIT / direct-origin as before.
                #
                # This ensures intermediate routers that forwarded a data=False query can receive
                # the reply and continue the recursive resolution.
                dest_name = parsed.get("Name")
                pending_ifaces = self.ns_query_table.get(dest_name, [])
                if pending_ifaces:
                    for p in list(pending_ifaces):
                        try:
                            port_int = int(p)
                        except Exception:
                            continue
                        # avoid sending back to self or to the sender
                        if port_int == self.port or (addr and len(addr) > 1 and port_int == addr[1]):
                            continue
                        try:
                            self.sock.sendto(packet, ("127.0.0.1", port_int))
                            self.log(f"[{self.name}] Forwarded ROUTE DATA for {dest_name} to NS-query iface port {port_int}")
                        except Exception as e:
                            self.log(f"[{self.name}] Error forwarding ROUTE DATA to NS-query iface {port_int}: {e}")
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
                            for port in set(pit_entry):
                                try:
                                    port_int = int(port)
                                except Exception:
                                    continue
                                # avoid forwarding back to self or sender
                                if port_int == self.port or (addr and len(addr) > 1 and port_int == addr[1]):
                                    continue
                                try:
                                    self.sock.sendto(packet, ("127.0.0.1", port_int))
                                    self.log(f"[{self.name}] Forwarded ROUTE DATA to PIT port {port_int}")
                                except Exception as e:
                                    self.log(f"[{self.name}] Error forwarding ROUTE DATA to PIT port {port_int}: {e}")
                return pkt_obj
        else:
            print(f"[{self.name}] Unknown packet type {packet_type} from {addr} at {timestamp}")
            self.log(f"[{self.name}] Unknown packet type {packet_type} from {addr} at {timestamp}")
    
    def get_neighbors(self):
        return self.neighbor_table

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
