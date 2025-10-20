import socket
import struct
import threading
import time
import json
from RouteDataPacket import RouteDataPacket
from datetime import datetime
from collections import deque, defaultdict

INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

def create_data_packet(seq_num, name, payload, flags=0x0):
    packet_type = DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, payload_size, name_length)
    return header + name_bytes + payload_bytes

def create_route_data_packet(seq_num, name, routing_info, flags=0x0):
        packet_type = ROUTING_DATA
        packet_type_flags = (packet_type << 4) | (flags & 0xF)
        seq_num = seq_num & 0xFF
        name_bytes = name.encode("utf-8")
        name_length = len(name_bytes) & 0xFF
        # routing_info is a path (list of node names)
        if isinstance(routing_info, list):
            # Convert list to comma-separated string
            routing_info_str = ",".join(routing_info)
            routing_info_bytes = routing_info_str.encode("utf-8")
        elif isinstance(routing_info, str):
            routing_info_bytes = routing_info.encode("utf-8")
        else:
            routing_info_bytes = routing_info
        info_size = len(routing_info_bytes) & 0xFF
        header = struct.pack("!BBBB", packet_type_flags, seq_num, info_size, name_length)
        return header + name_bytes + routing_info_bytes

def parse_interest_packet(packet):
    packet_type_flags, seq_num, name_length = struct.unpack("!BBB", packet[:3])
    name = packet[3:3+name_length].decode("utf-8")

    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
    }

def parse_hello_packet(packet):
    packet_type_flags, name_length = struct.unpack("!BB", packet[:2])
    name = packet[2:2 + name_length].decode("utf-8")
    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "NameLength": name_length,
        "Name": name
    }

def create_hello_packet(name):
    packet_type = HELLO
    flags = 0x0 # This is only for NS
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BB", packet_type_flags, name_length)
    packet = header + name_bytes
    return packet

def parse_update_packet(packet):
    packet_type_flags, name_length = struct.unpack("!BB", packet[:2])
    name = packet[2:2+name_length].decode("utf-8")
    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "Name": name
    }

class NameServer:
    def __init__(self, ns_name="/DLSU/NameServer1", host="127.0.0.1", port=6000, topo_file="topology.txt"):
        self.ns_name = ns_name
        self.host = host
        self.port = port
        self.topo_file = topo_file

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

        self.port_to_name = {}
        self.name_to_port = {}
        self.neighbor_table = {}

        self.graph = defaultdict(set)
        self._load_topology_file(self.topo_file)

        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

        #self.update_thread = threading.Thread(target=self._periodic_update, daemon=True)
        #self.update_thread.start()

        #print(f"[NS {self.ns_name}] up at {self.host}:{self.port}")
        #print(f"[NS {self.ns_name}] loaded topology with {len(self.graph)} nodes from {self.topo_file}")

    def _periodic_update(self):
        while self.running:
            domain = self.get_domains_from_name()
            for node in self.graph:
                # Handle nodes with multiple names (space-separated)
                node_names = node.split()
                #print(f"Node Names [{self.ns_name}]: {node_names}")
                for alias in node_names:
                    alias_domain = alias.lstrip('/').split('/')[0] if alias else ''
                    if alias_domain == domain and node != self.ns_name:
                        # Compute next hop for node to reach name server
                        path = self._shortest_path(node, self.ns_name)
                        if path and len(path) > 1:
                            next_hop = path[1]
                        else:
                            next_hop = self.ns_name
                        pkt = create_route_data_packet(seq_num=0, name=self.ns_name, routing_info=path)
                        # Send to node (if port known)
                        if node in self.name_to_port:
                            target_port = self.name_to_port[node]
                            self.sock.sendto(pkt, (self.host, target_port))
                            print(f"[NS {self.ns_name}] Sent ROUTE packet to {node} (alias: {alias}) at port {target_port} with next hop {next_hop}")
            time.sleep(10)

    def get_domains_from_name(self):
        for part in self.ns_name.split(" "):
              part = part.lstrip('/')
              top_domain = part.split('/')[0] if part else ''
        return top_domain

    def load_neighbors_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    node_name, ports_str = line.split(':', 1)
                    node_name = node_name.strip()
                    if node_name == self.ns_name:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                        for port in ports:
                            try:
                                pkt = create_hello_packet(self.ns_name)
                                self.sock.sendto(pkt, (self.host, int(port)))
                                #print(f"[{self.ns_name}] Sent HELLO packet to {self.host}:{port}")
                            except Exception as e:
                                print(f"[{self.ns_name}] Error sending HELLO packet to {self.host}:{port}: {e}")
                        #print(f"[{self.ns_name}] Loaded neighbors from {filename}: {ports}")
        except Exception as e:
            print(f"[{self.ns_name}] Error loading neighbors from {filename}: {e}")           

    def _load_topology_file(self, path):
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    node, nbrs = line.split(":", 1)
                    node = node.strip()
                    nbr_list = [n.strip() for n in nbrs.split(",") if n.strip()]
                    for n in nbr_list:
                        self.graph[node].add(n)
                        self.graph[n].add(node)
        except FileNotFoundError:
            print(f"[NS {self.ns_name}] WARNING: topology file '{path}' not found — start with an empty graph.")
        except Exception as e:
            print(f"[NS {self.ns_name}] ERROR loading topology: {e}")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                pkt_type = (data[0] >> 4) & 0xF
                if pkt_type == HELLO:
                    self._handle_hello(data, addr)
                elif pkt_type == UPDATE:
                    self._handle_update(data, addr)
                elif pkt_type == INTEREST:
                    self._handle_interest(data, addr)
                else:
                    pass
            except Exception as e:
                print(f"[NS {self.ns_name}] Listener error: {e}")

    def _handle_hello(self, packet, addr):
        parsed = parse_hello_packet(packet)
        node_name = parsed["Name"]
        flags = parsed["Flags"]

        self.port_to_name[addr] = node_name
        self.name_to_port[node_name] = addr[1]

        if flags == ACK_FLAG:
            # Add to neighbor table
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received
            self.neighbor_table[node_name] = timestamp
            #print(f"[NS {self.ns_name}] HELLO from {node_name} at {addr} (added as neighbor)")

    def _handle_update(self, packet, addr):
        parsed = parse_update_packet(packet)
        node_name = parsed["Name"]
        self.port_to_name[addr] = node_name
        self.name_to_port[node_name] = addr[1]
        print(f"[NS {self.ns_name}] UPDATE from {node_name} at {addr}")

    def _handle_interest(self, packet, addr):
        """
        Treat interest as a route request.
        - Source is determined from addr (using HELLO/UPDATE).
        - Name is the destination name.
        - Computes shortest path on graph from topology.txt.
        - Replies with data
        """
        parsed = parse_interest_packet(packet)
        dest_name = parsed["Name"]
        seq_num = parsed["SequenceNumber"]

        src_name = self.port_to_name.get(addr)
        if not src_name:
            # don't know who this is
            print(f"[NS {self.ns_name}] INTEREST from unknown {addr}. (No prior HELLO/UPDATE.)")
            src_name = "UNKNOWN"

        print(f"[NS {self.ns_name}] ROUTE REQ: {src_name} -> {dest_name}")

        path = self._shortest_path(src_name, dest_name)
        if not path:
            route_name = f"{self.ns_name}/Route({dest_name})"
            payload_obj = {"ok": False, "reason": "NameNotFound", "src": src_name, "dest": dest_name}
            payload = json.dumps(payload_obj)
            resp = create_data_packet(seq_num=seq_num, name=route_name, payload=payload, flags=ACK_FLAG)
            self.sock.sendto(resp, addr)
            print(f"[NS {self.ns_name}] No path. Sent DATA(NameNotFound) to {addr}")
            return

        next_hop = path[1] if len(path) >= 2 else dest_name
        next_hop_port = self.name_to_port.get(next_hop)  # may be None

        route_name = f"{self.ns_name}/Route({dest_name})"
        payload_obj = {
            "ok": True,
            "src": src_name,
            "dest": dest_name,
            "path": path,
            "next_hop": next_hop,
            "next_hop_port": next_hop_port
        }
        payload = json.dumps(payload_obj)
        resp = create_data_packet(seq_num=seq_num, name=route_name, payload=payload, flags=ACK_FLAG)
        self.sock.sendto(resp, addr)
        print(f"[NS {self.ns_name}] Sent ROUTE (next_hop={next_hop}, port={next_hop_port}) to {addr}")

    def _shortest_path(self, src, dest):
        if src not in self.graph or dest not in self.graph:
            return None
        if src == dest:
            return [src]
        q = deque([src])
        prev = {src: None}
        while q:
            u = q.popleft()
            for v in self.graph[u]:
                if v not in prev:
                    prev[v] = u
                    if v == dest:
                        path = [dest]
                        cur = dest
                        while prev[cur] is not None:
                            cur = prev[cur]
                            path.append(cur)
                        path.reverse()
                        return path
                    q.append(v)
        return None

    def stop(self):
        self.running = False
        try:
            self.sock.sendto(b"", (self.host, self.port))
        except Exception:
            pass
        self.sock.close()
    
    def get_neigbors(self):
        return self.neighbor_table

""" if __name__ == "__main__":
    ns = NameServer(ns_name="/DLSU/NameServer1", host="127.0.0.1", port=6000, topo_file="topology.txt")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        ns.stop() """
