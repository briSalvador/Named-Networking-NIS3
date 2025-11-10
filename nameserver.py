import socket
import struct
import threading
import time
import os
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

def create_interest_packet(seq_num, name, flags=0x0, origin_node="", data_flag=False):
    """
    Build an INTEREST packet (same encoding as Node.create_interest_packet).
    Used by NameServer to create encapsulated queries.
    """
    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)
    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF
    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes) & 0xFF
    data_flag_byte = b'\x01' if data_flag else b'\x00'
    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    pkt = header + name_bytes + struct.pack("!B", origin_length) + origin_bytes + data_flag_byte
    return pkt

def create_route_data_packet(seq_num, name, payload, flags=0x0):
    packet_type = ROUTING_DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    # payload should be a dict with at least 'origin_name' and 'path' fields
    if isinstance(payload, dict):
        payload_json = json.dumps(payload)
        payload_bytes = payload_json.encode("utf-8")
    else:
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, payload_size, name_length)
    return header + name_bytes + payload_bytes

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
        print(f"[NS parse_neighbor_update_packet] Error parsing packet: {e}")
        return None

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

        self.port_to_name[addr[1]] = node_name
        self.name_to_port[node_name] = addr[1]

        if flags == ACK_FLAG:
            # Add to neighbor table
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received
            self.neighbor_table[node_name] = timestamp
            #print(f"[NS {self.ns_name}] HELLO from {node_name} at {addr} (added as neighbor)")

    def _handle_update(self, packet, addr):
        """
        Handles neighbor UPDATE packets and updates the NS topology.
        Supports multi-name nodes and domain filtering.
        """
        try:
            parsed = parse_update_packet(packet)
            if not parsed:
                print(f"[NS {self.ns_name}] Failed to parse UPDATE from {addr}")
                return

            # Only process neighbor update packets (flag 0x2)
            if parsed["Flags"] != 0x2:
                return

            src_nodes = parsed.get("Name", [])
            neighbor_nodes = parsed.get("NeighborNames", [])

            if not src_nodes or not neighbor_nodes:
                print(f"[NS {self.ns_name}] Ignored UPDATE missing node or neighbor data from {addr}")
                return

            # Normalize node and neighbor lists
            src_nodes = [n.strip() for n in src_nodes if n.strip()]
            neighbor_nodes = [n.strip() for n in neighbor_nodes if n.strip()]

            # --- Check if update belongs to this NS's domain ---
            ns_domain = self.ns_name.strip("/").split("/")[0]  # e.g., "DLSU" from "/DLSU/NameServer1"

            # Determine if at least one of the node's names belongs to this NS's domain
            in_domain = any(
                n.strip("/").split("/")[0] == ns_domain for n in src_nodes
            )

            if not in_domain:
                print(f"[NS {self.ns_name}] Ignored UPDATE not in domain ({ns_domain}): {' '.join(src_nodes)}")
                return
            
            combined_name = " ".join(src_nodes)

            # Register node-port mapping
            self.port_to_name[addr[1]] = combined_name
            self.name_to_port[combined_name] = addr[1]

            # Ensure node exists in the graph
            if combined_name not in self.graph or not isinstance(self.graph[combined_name], set):
                self.graph[combined_name] = set()

            # Add bidirectional edges
            combined_neighbor = " ".join(neighbor_nodes)

            # Add connection both ways
            self.graph[combined_name].add(combined_neighbor)
            if combined_neighbor not in self.graph:
                self.graph[combined_neighbor] = set()
            self.graph[combined_neighbor].add(combined_name)

            print(f"[NS {self.ns_name}] UPDATE accepted: {combined_name} ↔ {combined_neighbor}")

            # --- Save topology to file ---
            self._write_topology_to_file()

        except Exception as e:
            print(f"[NS {self.ns_name}] Error handling UPDATE: {e}")

    def _write_topology_to_file(self):
        """
        Writes the current topology graph to '<ns_name>_topology.txt'.
        - Each node (including aliases) appears on its own line, even if neighbor sets are identical.
        - Multi-name (border router) nodes are grouped as one name with spaces (not commas).
        - When border routers appear as neighbors, their full grouped names are shown.
        """
        try:
            safe_name = self.ns_name.replace("/", "_").strip("_")
            filename = f"{safe_name}_topology.txt"
            dirpath = os.path.dirname(filename)
            if dirpath and not os.path.exists(dirpath):
                os.makedirs(dirpath, exist_ok=True)

            # Determine the NS's own domain, e.g., "DLSU" from "/DLSU/NameServer1"
            ns_domain = self.ns_name.strip("/").split("/")[0] if self.ns_name else ""

            # Build alias mapping: each alias points to its full multi-name (border router) group
            alias_map = {}
            for port, aliases_str in getattr(self, "port_to_name", {}).items():
                if isinstance(aliases_str, str):
                    aliases = [a.strip() for a in aliases_str.split() if a.strip()]
                elif isinstance(aliases_str, (list, tuple)):
                    aliases = [a.strip() for a in aliases_str if a.strip()]
                else:
                    continue
                if not aliases:
                    continue
                combined = " ".join(sorted(set(aliases)))
                for a in aliases:
                    alias_map[a] = combined

            def top_level(name):
                segs = name.strip("/").split("/")
                return segs[0] if segs else ""

            lines = []
            written = set()

            for node in sorted(self.graph.keys()):
                if not isinstance(node, str) or not node.startswith("/"):
                    continue
                if node in written:
                    continue

                # Get grouped alias name if exists
                node_group = alias_map.get(node, node)

                # Mark all names in this group as written
                for part in node_group.split():
                    written.add(part)

                # Skip nodes outside this NS's domain
                if not any(top_level(a) == ns_domain for a in node_group.split()):
                    continue

                # Gather all neighbors for this node
                neighbors = self.graph.get(node, set())

                # Replace any alias neighbors with their grouped form
                expanded_neighbors = set()
                for n in neighbors:
                    if not isinstance(n, str) or not n.startswith("/"):
                        continue
                    expanded_neighbors.add(alias_map.get(n, n))

                # Sort for consistent output
                sorted_neighbors = sorted(expanded_neighbors)

                # Build output line
                neighbor_str = ", ".join(sorted_neighbors)
                lines.append(f"{node_group}: {neighbor_str}\n")

            # Write topology file (overwrite existing)
            with open(filename, "w", encoding="utf-8") as f:
                f.writelines(lines)

            print(f"[NS {self.ns_name}] Topology updated and saved to {filename}")

        except Exception as e:
            print(f"[NS {self.ns_name}] Error writing topology file: {e}")

    def strip_last_level(self, path):
        """Utility to remove the last level from a hierarchical name."""
        if not path:
            return path
        segments = path.strip('/').split('/')
        if len(segments) > 1:
            return '/' + '/'.join(segments[:-1])
        return path

    def _handle_interest(self, packet, addr):
        """
        Treat interest as a route request.
        - Source is determined from addr (using HELLO/UPDATE).
        - Name is the destination name.
        - Computes shortest path on graph from topology.txt.
        - Replies with ROUTING_DATA or forwards INTEREST to border router if dest is outside domain.
        """
        parsed = parse_interest_packet(packet)
        dest_name = parsed["Name"]

        seq_num = parsed["SequenceNumber"]

        src_name = parsed["OriginNode"]
        if not src_name:
            # don't know who this is
            print(f"[NS {self.ns_name}] INTEREST from unknown {addr}. (No prior HELLO/UPDATE.)")
            src_name = "UNKNOWN"

        print(f"[NS {self.ns_name}] ROUTE REQ: {src_name} -> {dest_name}")

        original_name = dest_name
        # destination for routing calculation is the parent entity (strip file/last level)
        dest_node = self.strip_last_level(dest_name)

        # helper: extract top-level domain from a name like "/ADMU/Gonzaga/..."
        def _top_domain(name):
            if not name:
                return None
            s = name.lstrip("/")
            parts = s.split("/")
            return parts[0] if parts else None

        my_top = _top_domain(self.ns_name)
        target_top = _top_domain(dest_node)

        # If the request is for a name outside this NS domain, attempt to forward to a border router
        if target_top and my_top and target_top != my_top:
            # find candidate border routers (nodes whose any alias has the target top domain)
            border_candidates = []
            for node in self.graph.keys():
                # node may contain space-separated aliases
                for alias in node.split():
                    if _top_domain(alias) == target_top:
                        border_candidates.append(node)
                        break

            # Try candidates, find a path and a reachable port along that path (including aliases)
            def _find_port_for_path(path_nodes):
                # Check each hop in the path (after source) for any known port
                # prefer hop nearest to source (path_nodes[1], path_nodes[2], ...)
                for hop in path_nodes[1:]:
                    # try exact mapping for hop (may be a multi-alias string)
                    if hop in self.name_to_port:
                        return self.name_to_port[hop], hop
                    # try aliases
                    for alias in hop.split():
                        if alias in self.name_to_port:
                            return self.name_to_port[alias], alias
                return None, None

            forwarded_any = False
            for candidate in border_candidates:
                # 1) Try path from THIS NS to the candidate (so NS can send to a neighbor it knows)
                path_from_ns = self._shortest_path(self.ns_name, candidate)
                if path_from_ns and len(path_from_ns) > 1:
                    port, resolved_name = _find_port_for_path(path_from_ns)
                    if port:
                        try:
                            # Encapsulate the original destination with the candidate (border) alias.
                            # Format: "ENCAP:<candidate>|<original_name>"
                            enc_name = f"ENCAP:{candidate}|{original_name}"
                            enc_pkt = create_interest_packet(seq_num=seq_num, name=enc_name, flags=parsed.get("Flags",0), origin_node=src_name, data_flag=False)
                            self.sock.sendto(enc_pkt, (self.host, int(port)))
                            print(f"[NS {self.ns_name}] ENCAP-FORWARDED INTEREST for {original_name} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_ns]")
                            return
                        except Exception as e:
                            print(f"[NS {self.ns_name}] Error forwarding INTEREST to {resolved_name}:{port} - {e}")

                # 2) Fallback: try path from the original source to the candidate and search ANY hop the NS knows
                path_to_border = self._shortest_path(src_name, candidate)
                if path_to_border:
                    # search entire path (not only hops after src) for any known node/alias
                    port, resolved_name = None, None
                    for hop in path_to_border:
                        if hop in self.name_to_port:
                            port, resolved_name = self.name_to_port[hop], hop
                            break
                        for alias in hop.split():
                            if alias in self.name_to_port:
                                port, resolved_name = self.name_to_port[alias], alias
                                break
                        if port:
                            break
                    if port:
                        try:
                            enc_name = f"ENCAP:{candidate}|{original_name}"
                            enc_pkt = create_interest_packet(seq_num=seq_num, name=enc_name, flags=parsed.get("Flags",0), origin_node=src_name, data_flag=False)
                            self.sock.sendto(enc_pkt, (self.host, int(port)))
                            print(f"[NS {self.ns_name}] ENCAP-FORWARDED INTEREST for {original_name} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_src]")
                            return
                        except Exception as e:
                            print(f"[NS {self.ns_name}] Error forwarding INTEREST to {resolved_name}:{port} - {e}")

                # 3) As fallback, check candidate aliases themselves (direct mapping)
                for alias in candidate.split():
                    if alias in self.name_to_port:
                        try:
                            enc_name = f"ENCAP:{candidate}|{original_name}"
                            enc_pkt = create_interest_packet(seq_num=seq_num, name=enc_name, flags=parsed.get("Flags",0), origin_node=src_name, data_flag=False)
                            self.sock.sendto(enc_pkt, (self.host, int(self.name_to_port[alias])))
                            print(f"[NS {self.ns_name}] ENCAP-FORWARDED INTEREST for {original_name} -> candidate alias {alias} (port {self.name_to_port[alias]}) [candidate_alias]")
                            return
                        except Exception as e:
                            print(f"[NS {self.ns_name}] Error forwarding INTEREST to alias {alias} - {e}")

            # If we couldn't forward to any border router because there were no known ports on path/candidates
            print(f"[NS {self.ns_name}] Target domain {target_top} not local and no reachable border port found — continuing resolution attempt.")

        # Normal handling: compute path to destination inside this domain
        path = self._shortest_path(src_name, dest_node)
        if not path:
            route_name = dest_node
            payload_obj = {"ok": False, "reason": "NameNotFound", "src": src_name, "dest": dest_node}
            payload = json.dumps(payload_obj)
            resp = create_route_data_packet(seq_num=seq_num, name=original_name, payload=payload, flags=ACK_FLAG)
            self.sock.sendto(resp, addr)
            print(f"[NS {self.ns_name}] No path. Sent DATA(NameNotFound) to {addr}")
            return

        next_hop = path[1] if len(path) >= 2 else dest_node
        origin_name = parsed["OriginNode"]
        route_payload = {
            "origin_name": origin_name,
            "path": path,
            "dest": original_name,
            "next_hop": next_hop,
        }
        resp = create_route_data_packet(seq_num=seq_num, name=original_name, payload=route_payload, flags=ACK_FLAG)

        self.sock.sendto(resp, addr)
        print(f"[NS {self.ns_name}] Sent ROUTE (next_hop={next_hop}) to {addr}")
        
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
