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

# TODO: FIB, CS (Dict), Packet objects, Routes, Neighbor Table, 
# Next hops, Fragmentation, 
# Timestamps for receiving packets

# Will add hop count for neighbor discovery later

def create_interest_packet(seq_num, name, flags=0x0):
    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = header + name_bytes
    return packet

FRAGMENT_SIZE = 1500

def create_data_packet(seq_num, name, payload, flags=0x0, fragment_num=1, total_fragments=1):
    packet_type = DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    # Add fragment info (fragment_num, total_fragments)
    header = struct.pack("!BBBBBB", packet_type_flags, seq_num, payload_size, name_length, fragment_num, total_fragments)
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
    # Unpack fragment info
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

class Node:
    def __init__(self, name, host="127.0.0.1", port=0):
        self.name = name
        self.host = host
        self.port = port if port != 0 else self._get_free_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.neighbor_table = {}

        # Tables
        self.fib = {}  # {name: {"NextHops": [port, ...], "ExpirationTime": ...}}
        self.cs = {}
        self.pit = {}
        self.fragment_buffer = {}
        self.fib_interfaces = []
        self.pit_interfaces = []

        print(f"[{self.name}] Node started at {self.host}:{self.port}")

        # Start background thread for listening
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

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
        else:
            pkt = create_data_packet(seq_num, name, payload, flags, 1, 1)
            self.sock.sendto(pkt, target)
            print(f"[{self.name}] Sent DATA packet to {target}")
        return True
    
    def add_fib(self, name, interface, exp_time):
        # interface is the next hop port (int)
        if name not in self.fib:
            self.fib[name] = {
                "NextHops": [],
                "ExpirationTime": exp_time
            }
        if interface not in self.fib[name]["NextHops"]:
            self.fib[name]["NextHops"].append(interface)
        print(f"[{self.name}] FIB updated: {self.fib}")

    def get_next_hops(self, name):
        """Return a list of next hop ports for a given name/prefix."""
        if name in self.fib:
            return self.fib[name]["NextHops"]
        return []

    def forward_interest(self, pkt_obj, target=None):
        # If target is None, use FIB to determine next hops
        if target is None:
            next_hops = self.get_next_hops(pkt_obj.name)
            for port in next_hops:
                pkt = create_interest_packet(pkt_obj.seq_num, pkt_obj.name, pkt_obj.flags)
                self.sock.sendto(pkt, ("127.0.0.1", port))
                print(f"[{self.name}] Forwarded INTEREST packet for {pkt_obj.name} to next hop port {port}")
        else:
            pkt = create_interest_packet(pkt_obj.seq_num, pkt_obj.name, pkt_obj.flags)
            self.sock.sendto(pkt, target)
            print(f"[{self.name}] Forwarded INTEREST packet to {target}")
            # Direct forwarding (legacy)
            # print(f"[{self.name}] Forwarded INTEREST packet to {target}")

    def receive_packet(self, packet, addr=None):
        # Peek packet type
        packet_type = (packet[0] >> 4) & 0xF
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received

        if addr:
            self.neighbor_table[addr] = timestamp
            print(f"[{self.name}] Neighbor Table updated: {self.neighbor_table}")

        if packet_type == INTEREST:  # Interest
            parsed = parse_interest_packet(packet)
            pkt_obj = InterestPacket(
                seq_num=parsed["SequenceNumber"],
                name=parsed["Name"],
                flags=parsed["Flags"],
                timestamp=timestamp
            )
            print(f"[{self.name}] Received INTEREST from {addr} at {timestamp}")
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
                # Use next hop(s) from FIB
                next_hops = self.get_next_hops(pkt_obj.name)
                for port in next_hops:
                    print(f"[{self.name}] Forwarding INTEREST for {parsed['Name']} via FIB to next hop port: {port}")
                    self.forward_interest(pkt_obj, ("127.0.0.1", port))

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
            # Fragmentation handling
            frag_key = (parsed["SequenceNumber"], parsed["Name"])
            if parsed["TotalFragments"] > 1:
                if frag_key not in self.fragment_buffer:
                    self.fragment_buffer[frag_key] = [None] * parsed["TotalFragments"]
                self.fragment_buffer[frag_key][parsed["FragmentNum"]-1] = parsed["Payload"]
                print(f"[{self.name}] Received DATA fragment {parsed['FragmentNum']}/{parsed['TotalFragments']} from {addr}")
                if all(frag is not None for frag in self.fragment_buffer[frag_key]):
                    # All fragments received, reassemble
                    full_payload = ''.join(self.fragment_buffer[frag_key])
                    print(f"[{self.name}] All fragments received. Reassembled payload: {full_payload}")
                    del self.fragment_buffer[frag_key]
            else:
                print(f"[{self.name}] Received DATA from {addr} at {timestamp}")
                print(f"  Parsed: {parsed}")
                print(f"  Object: {pkt_obj}")
            return pkt_obj
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
        # interface is the next hop port (int)
        if name not in self.fib:
            self.fib[name] = {
                "NextHops": [],
                "ExpirationTime": exp_time
            }
        if interface not in self.fib[name]["NextHops"]:
            self.fib[name]["NextHops"].append(interface)
        print(f"[{self.name}] FIB updated: {self.fib}")

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
