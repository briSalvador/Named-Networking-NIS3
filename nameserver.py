import socket
import struct
import threading
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
    flags = 0x0
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
        #self._load_topology_file(self.topo_file)

        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

        print(f"[NS {self.ns_name}] up at {self.host}:{self.port}")
        print(f"[NS {self.ns_name}] loaded topology with {len(self.graph)} nodes from {self.topo_file}")

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
                            #self.add_neighbor(self.host, int(port))
                            try:
                                pkt = create_hello_packet(self.ns_name)
                                self.sock.sendto(pkt, (self.host, int(port)))
                                print(f"[{self.ns_name}] Sent HELLO packet to {self.host}:{port}")
                            except Exception as e:
                                print(f"[{self.ns_name}] Error sending HELLO packet to {self.host}:{port}: {e}")
                        print(f"[{self.ns_name}] Loaded neighbors from {filename}: {ports}")
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
        self.port_to_name[addr] = node_name
        self.name_to_port[node_name] = addr

        # Add to neighbor table
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received
        self.neighbor_table[node_name] = timestamp
        print(f"[NS {self.ns_name}] HELLO from {node_name} at {addr} (added as neighbor)")

    def _handle_update(self, packet, addr):
        parsed = parse_update_packet(packet)
        node_name = parsed["Name"]
        self.port_to_name[addr] = node_name
        self.name_to_port[node_name] = addr
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
            payload = f'{{"ok": false, "reason": "NameNotFound", "src": "{src_name}", "dest": "{dest_name}"}}'
            resp = create_data_packet(seq_num=seq_num, name=route_name, payload=payload, flags=ACK_FLAG)
            self.sock.sendto(resp, addr)
            print(f"[NS {self.ns_name}] No path. Sent DATA(NameNotFound) to {addr}")
            return

        next_hop = path[1] if len(path) >= 2 else dest_name
        next_hop_port = self.name_to_port.get(next_hop)

        route_name = f"{self.ns_name}/Route({dest_name})"
        payload = (
            '{'
            f'"ok": true, '
            f'"src": "{src_name}", '
            f'"dest": "{dest_name}", '
            f'"path": {path}, '
            f'"next_hop": "{next_hop}", '
            f'"next_hop_port": {next_hop_port[1] if next_hop_port else "null"}'
            '}'
        )
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
