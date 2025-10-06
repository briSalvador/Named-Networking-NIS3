import socket
import threading
import struct
import time
from DataPacket import DataPacket
from InterestPacket import InterestPacket
from Packet import Packet
from datetime import datetime

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

# TODO (As of Sep 30): 
# FIB: Add hop count for FIB entries so that new routes are compared with existing ones and replaced
# if new route is shorter.

def create_interest_packet(seq_num, name, flags=0x0):
    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = header + name_bytes
    return packet

def create_data_packet(seq_num, name, payload, flags=0x0):
    packet_type = DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, payload_size, name_length)
    packet = header + name_bytes + payload_bytes
    return packet

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

def parse_data_packet(packet):
    packet_type_flags, seq_num, payload_size, name_length = struct.unpack("!BBBB", packet[:4])

    name_start = 4
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
    }

# ---------------- HELLO / UPDATE Packets ----------------
def create_hello_packet(name):
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

def create_update_packet(name):
    packet_type = UPDATE
    flags = 0x0
    packet_type_flags = (packet_type << 4) | flags
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)
    header = struct.pack("!BB", packet_type_flags, name_length)
    return header + name_bytes

def parse_update_packet(packet):
    packet_type_flags, name_length = struct.unpack("!BB", packet[:2])
    name = packet[2:2+name_length].decode("utf-8")
    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "Name": name
    }

class Node:
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

    def __init__(self, name, host="127.0.0.1", port=0, broadcast_port=9999):
        self.name = name
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

        # Tables
        self.fib = {}
        self.cs = {}
        self.pit = {}
        self.fib_interfaces = []
        self.pit_interfaces = []

        #print(f"[{self.name}] Node started at {self.host}:{self.port} and listening for broadcasts on port {self.broadcast_port}")

        # Start background threads for listening
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

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
        """Continuously listen for incoming packets."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.receive_packet(data, addr)
            except Exception as e:
                print(f"[{self.name}] Listener stopped: {e}")
                break

    def send_interest(self, seq_num, name, flags=0x0, target=("127.0.0.1", 0)):
        pkt = create_interest_packet(seq_num, name, flags)
        self.sock.sendto(pkt, target)
        print(f"[{self.name}] Sent INTEREST packet to {target}")
        return pkt

    def send_data(self, seq_num, name, payload, flags=0x0, target=("127.0.0.1", 0)):
        pkt = create_data_packet(seq_num, name, payload, flags)
        self.sock.sendto(pkt, target)
        print(f"[{self.name}] Sent DATA packet to {target}")
        return pkt
    
    def forward_interest(self, pkt_obj, target=("127.0.0.1", 0)):
        #pkt = create_interest_packet(pkt_obj.seq_num, pkt_obj.name, pkt_obj.flags)
        #self.sock.sendto(pkt, target)
        print(f"[{self.name}] Forwarded INTEREST packet to {target}")

    def receive_packet(self, packet, addr=None):
        # Peek packet type
        packet_type = (packet[0] >> 4) & 0xF
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received

        #if addr:
            #self.neighbor_table[addr] = timestamp
            #print(f"[{self.name}] Neighbor Table updated: {self.neighbor_table}")

        if packet_type == INTEREST:  # Interest
            parsed = parse_interest_packet(packet)
            pkt_obj = InterestPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            print(f"[{self.name}] Received INTEREST from port {addr[1]} at {timestamp}")
            print(f"  Parsed: {parsed}")
            print(f"  Object: {pkt_obj}")

            # Check tables
            table, data = self.check_tables(parsed["Name"])
            #print("Table: " + str(table) + " Data: " + str(data))

            if table == "CS":
                print(f"[{self.name}] Data found in CS for {parsed['Name']}, sending DATA back to {addr}")
                self.send_data(
                    seq_num=pkt_obj.seq_num,
                    name=pkt_obj.name,
                    payload=data,
                    flags=ACK_FLAG,
                    target=addr
                )

            if pkt_obj.name not in self.pit:
                self.pit_interfaces.append(addr[1])
                self.pit[pkt_obj.name] = list(self.pit_interfaces)
                print(f"[{self.name}] Added {pkt_obj.name} to PIT with interfaces: {self.pit_interfaces}")
            elif pkt_obj.name in self.pit and addr[1] not in self.pit_interfaces:
                self.pit_interfaces.append(addr[1])
                self.pit[pkt_obj.name] = list(self.pit_interfaces)
                print(f"[{self.name}] Updated PIT for {pkt_obj.name} with new interface: {addr[1]}")

            if table == "FIB":
                if pkt_obj.name in self.fib:
                    for interface in self.fib[pkt_obj.name]['Interfaces']:
                        print(f"[{self.name}] Forwarding INTEREST for {parsed['Name']} via FIB to interface: {interface}")
                        self.forward_interest(pkt_obj, ("127.0.0.1", interface))

            return pkt_obj
        elif packet_type == DATA:  # Data
            parsed = parse_data_packet(packet)
            pkt_obj = DataPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                payload=parsed["Payload"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            print(f"[{self.name}] Received DATA from {addr} at {timestamp}")
            print(f"  Parsed: {parsed}")
            print(f"  Object: {pkt_obj}")
            return pkt_obj
        elif packet_type == HELLO:
            parsed = parse_hello_packet(packet)
            neighbor_name = parsed["Name"]
            self.neighbor_table[neighbor_name] = timestamp
            print(f"[{self.name}] Received HELLO from {neighbor_name} at {addr}")

            # Add neighbor to FIB
            self.add_fib(neighbor_name, addr[1], exp_time=5000)

            # Send UPDATE back
            update_pkt = create_update_packet(self.name)
            self.sock.sendto(update_pkt, addr)
            print(f"[{self.name}] Sent UPDATE back to {neighbor_name} at {addr}")
        elif packet_type == UPDATE:
            parsed = parse_update_packet(packet)
            neighbor_name = parsed["Name"]
            self.neighbor_table[neighbor_name] = timestamp
            print(f"[{self.name}] Received UPDATE from {neighbor_name} at {addr}")

            # Add/update FIB
            self.add_fib(neighbor_name, addr[1], exp_time=5000)
            print(f"[{self.name}] Updated FIB with neighbor {neighbor_name} on {addr}")
        else:
            print(f"[{self.name}] Unknown packet type {packet_type} from {addr} at {timestamp}")
    
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
    
    def stop(self):
        self.running = False
        try:
            self.sock.sendto(b"", (self.host, self.port))
        except Exception:
            pass
        time.sleep(0.1)
        self.sock.close()

    def add_fib(self, name, interface, exp_time):
        self.fib_interfaces.append(interface)
        self.fib[name] = {
            "Interfaces": list(self.fib_interfaces),
            "ExpirationTime": exp_time
        }

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

    def remove_pit(self, name):
        if name in self.pit:
            del self.pit[name]

    def check_tables(self, name):
        if name in self.cs:
            return "CS", self.cs[name]
        elif name in self.pit:
            return "PIT", self.pit[name]
        elif name in self.fib:
            return "FIB", self.fib[name]
        else:
            return None, None
        
    def add_neighbor(self, addr, port):
        key = (addr, port)
        if key not in self.neighbor_table:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            self.neighbor_table[key] = timestamp
            print(f"[{self.name}] Added neighbor {key} to neighbor_table.")
        else:
            print(f"[{self.name}] Neighbor {key} already exists in neighbor_table.")