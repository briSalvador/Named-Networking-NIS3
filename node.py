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

def create_interest_packet(seq_num, name, flags=0x0, origin_node=""):
    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes)

    # Add origin_length as 1 byte after name
    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = header + name_bytes + struct.pack("!B", origin_length) + origin_bytes
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

    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "OriginNode": origin_node,
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
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    node_name, ports_str = line.split(':', 1)
                    node_name = node_name.strip()
                    if node_name == self.name:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                        for port in ports:
                            #self.add_neighbor(self.host, int(port))
                            try:
                                pkt = create_hello_packet(self.name)
                                self.sock.sendto(pkt, (self.host, int(port)))
                                print(f"[{self.name}] Sent HELLO packet to {self.host}:{port}")
                            except Exception as e:
                                print(f"[{self.name}] Error sending HELLO packet to {self.host}:{port}: {e}")
                        print(f"[{self.name}] Loaded neighbors from {filename}: {ports}")
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
                        entry = self.buffer[0]
                        if entry["status"] == "resolved":
                            pkt = entry["packet"]
                            dest = entry["destination"]
                            next_hop = entry.get("next_hop")
                            if next_hop:
                                send_addr = ("127.0.0.1", int(next_hop))
                                print(f"[{self.name}] Processing buffered packet to {dest} -> forwarding to next hop {next_hop}")
                                try:
                                    self.sock.sendto(pkt, send_addr)
                                    self.log(f"[{self.name}] Forwarded buffered packet for {dest} to next hop {next_hop}")
                                except Exception as e:
                                    print(f"[{self.name}] Error forwarding buffered packet to {send_addr}: {e}")
                                    self.log(f"[{self.name}] Error forwarding buffered packet to {send_addr}: {e}")
                            else:
                                print(f"[{self.name}] Buffered entry for {dest} resolved but no next_hop found; dropping.")
                                self.log(f"[{self.name}] Buffered entry for {dest} resolved but no next_hop found; dropping.")
                            self.buffer.popleft()
                        else:
                            self.receive_packet(entry["packet"], entry["addr"])
                            self.buffer.popleft()
            except Exception as e:
                print(f"[{self.name}] Buffer processing error: {e}")
            time.sleep(1)

    def send_interest(self, seq_num, name, flags=0x0, target=("127.0.0.1", 0)):
        pkt = create_interest_packet(seq_num, name, flags, origin_node=self.name)
        self.sock.sendto(pkt, target)
        print(f"[{self.name}] Sent INTEREST packet to {target}")
        self.log(f"[{self.name}] Sent INTEREST packet to {target}")
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
    
    def add_fib(self, name, interface, exp_time, hop_count):
        # interface is the next hop port (int)
        if name not in self.fib:
            self.fib[name] = {
                "NextHops": interface,
                "ExpirationTime": exp_time,
                "HopCount": hop_count
            }
        elif name in self.fib and hop_count < self.fib[name]["HopCount"]:
            self.fib[name] = {
                "NextHops": interface,
                "ExpirationTime": exp_time,
                "HopCount": hop_count
            }

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
            pkt = create_interest_packet(pkt_obj.seq_num, pkt_obj.name, pkt_obj.flags, origin_node=getattr(pkt_obj, 'origin_node', self.name))
            self.sock.sendto(pkt, ("127.0.0.1", int(port)))
            print(f"[{self.name}] Forwarded INTEREST packet for {pkt_obj.name} to next hop port {port}")
            self.log(f"[{self.name}] Forwarded INTEREST packet for {pkt_obj.name} to next hop port {port}")
        else:
            pkt = create_interest_packet(pkt_obj.seq_num, pkt_obj.name, pkt_obj.flags, origin_node=getattr(pkt_obj, 'origin_node', self.name))
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
            pkt_obj = InterestPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            print(f"[{self.name}] Received INTEREST from port {addr[1]} at {timestamp}")
            self.log(f"[{self.name}] Received INTEREST from port {addr[1]} at {timestamp}")

            table, data = self.check_tables(parsed["Name"])

            # existing PIT/CS handling
            if pkt_obj.name not in self.pit:
                self.pit_interfaces.append(addr[1])
                self.pit[pkt_obj.name] = list(self.pit_interfaces)
                print(f"[{self.name}] Added {pkt_obj.name} to PIT with interfaces: {self.pit_interfaces}")
                self.log(f"[{self.name}] Added {pkt_obj.name} to PIT with interfaces: {self.pit_interfaces}")
            else:
                if addr[1] not in self.pit_interfaces:
                    self.pit_interfaces.append(addr[1])
                    self.pit[pkt_obj.name] = list(self.pit_interfaces)
                    print(f"[{self.name}] Updated PIT for {pkt_obj.name} with new interface: {addr[1]}")
                    self.log(f"[{self.name}] Updated PIT for {pkt_obj.name} with new interface: {addr[1]}")

            if table is None:
                # Add to buffer and forward to domain NameServer if the name is within node's domain(s)
                self.add_to_buffer(packet, addr, reason="No FIB route available")
                dest_domain = parsed["Name"].lstrip('/').split('/')[0] if parsed["Name"].startswith('/') else None
                if dest_domain and dest_domain in self.domains:
                    ns_name = f"/{dest_domain}/NameServer1"
                    fib_entry = self.fib.get(ns_name)
                    if fib_entry:
                        ns_port = fib_entry["NextHops"]
                        try:
                            self.sock.sendto(create_interest_packet(parsed["SequenceNumber"], parsed["Name"], parsed["Flags"], origin_node=parsed.get("OriginNode", self.name)), ("127.0.0.1", int(ns_port)))
                            print(f"[{self.name}] Forwarded INTEREST for {parsed['Name']} to domain NameServer {ns_name} via FIB at port {ns_port}")
                            self.log(f"[{self.name}] Forwarded INTEREST for {parsed['Name']} to domain NameServer {ns_name} via FIB at port {ns_port}")
                            # mark buffered entries as forwarded to NS
                            with self.buffer_lock:
                                for entry in self.buffer:
                                    if entry["destination"] == parsed["Name"]:
                                        entry["forwarded_to_ns"] = True
                        except Exception as e:
                            print(f"[{self.name}] Error forwarding INTEREST to NS via FIB: {e}")
                            self.log(f"[{self.name}] Error forwarding INTEREST to NS via FIB: {e}")
                    else:
                        print(f"[{self.name}] No FIB entry for domain NameServer {ns_name} (domain={dest_domain})")
                        self.log(f"[{self.name}] No FIB entry for domain NameServer {ns_name} (domain={dest_domain})")
                return  # buffer unknown routes

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
                self.forward_interest(pkt_obj, ("127.0.0.1", int(next_hop)))
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
            # Only process if origin_name matches this node
            if origin_name == self.name:
                if isinstance(route_info, dict) and ("next_hop" in route_info or "next_hop_port" in route_info):
                    dest = route_info.get("dest")
                    next_hop = route_info.get("next_hop")
                    next_hop_port = None
                    # Try to get next_hop_port from FIB if next_hop is a node name
                    if next_hop:
                        fib_entry = self.fib.get(next_hop)
                        if fib_entry:
                            next_hop_port = fib_entry["NextHops"]
                    if not next_hop_port:
                        # fallback to next_hop_port in route_info
                        next_hop_port = route_info.get("next_hop_port")
                    if dest and next_hop_port:
                        try:
                            nh = int(next_hop_port)
                            self.add_fib(dest, nh, exp_time=5000, hop_count=1)
                            print(f"[{self.name}] Stored FIB entry for {dest} -> next hop {nh}")
                            self.log(f"[{self.name}] Stored FIB entry for {dest} -> next hop {nh}")
                            # resolve buffered entries for this dest and forward immediately
                            with self.buffer_lock:
                                to_remove = []
                                for entry in list(self.buffer):
                                    if entry["destination"] == dest:
                                        entry["status"] = "resolved"
                                        entry["next_hop"] = nh
                                        try:
                                            self.sock.sendto(entry["packet"], ("127.0.0.1", nh))
                                            print(f"[{self.name}] Forwarded buffered INTEREST for {dest} to next hop {nh}")
                                            self.log(f"[{self.name}] Forwarded buffered INTEREST for {dest} to next hop {nh}")
                                        except Exception as e:
                                            print(f"[{self.name}] Error forwarding buffered INTEREST to {nh}: {e}")
                                        to_remove.append(entry)
                                for entry in to_remove:
                                    if entry in self.buffer:
                                        self.buffer.remove(entry)
                        except Exception as e:
                            print(f"[{self.name}] Error storing FIB from NS reply: {e}")
                    else:
                        print(f"[{self.name}] Route reply indicates no path to {route_info.get('dest')}")
                        self.log(f"[{self.name}] Route reply indicates no path to {route_info.get('dest')}")
                self.add_fib(pkt_obj.name, addr[1], exp_time=5000, hop_count=len(pkt_obj.path))
                return pkt_obj
            else:
                # If not for this node, forward the ROUTING_DATA packet to PIT entries
                print(f"[{self.name}] ROUTING_DATA origin_name mismatch ({origin_name}), forwarding to PIT entries.")
                self.log(f"[{self.name}] ROUTING_DATA origin_name mismatch ({origin_name}), forwarding to PIT entries.")
                for pit_entry in self.pit.values():
                    if isinstance(pit_entry, list):
                        for port in pit_entry:
                            try:
                                self.sock.sendto(packet, ("127.0.0.1", port))
                                print(f"[{self.name}] Forwarded ROUTING_DATA to PIT port {port}")
                                self.log(f"[{self.name}] Forwarded ROUTING_DATA to PIT port {port}")
                            except Exception as e:
                                print(f"[{self.name}] Error forwarding ROUTING_DATA to PIT port {port}: {e}")
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

        # 3. FIB: Match interest name with FIB entry except last level (data name)
        def strip_last_level(path):
            if not path:
                return path
            segments = path.strip('/').split('/')
            if len(segments) > 1:
                return '/' + '/'.join(segments[:-1])
            return path

        fib_interest = strip_last_level(name)
        best_key = None
        best_score = float('inf')
        for key in self.fib.keys():
            fib_key = strip_last_level(key)
            score = self.levenshtein_distance(fib_interest, fib_key)
            if score < 2 and score < best_score:
                best_score = score
                best_key = key
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