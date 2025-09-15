import socket
import threading
import struct

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
        "packet_type": packet_type,
        "flags": flags,
        "seq_num": seq_num,
        "name_length": name_length,
        "name": name
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
        "packet_type": packet_type,
        "flags": flags,
        "seq_num": seq_num,
        "payload_size": payload_size,
        "name_length": name_length,
        "name": name,
        "payload": payload.decode("utf-8", errors="ignore")
    }

class Node:
    def __init__(self, name, host="127.0.0.1", port=0):
        self.name = name
        self.host = host
        self.port = port if port != 0 else self._get_free_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

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
        pkt = create_data_packet(seq_num, name, payload, flags)
        self.sock.sendto(pkt, target)
        print(f"[{self.name}] Sent DATA packet to {target}")
        return pkt

    def receive_packet(self, packet, addr=None):
        # Peek packet type
        packet_type = (packet[0] >> 4) & 0xF

        if packet_type == 0x1:  # Interest
            parsed = parse_interest_packet(packet)
            print(f"[{self.name}] Received INTEREST from {addr}: {parsed}")
        elif packet_type == 0x2:  # Data
            parsed = parse_data_packet(packet)
            print(f"[{self.name}] Received DATA from {addr}: {parsed}")
        else:
            print(f"[{self.name}] Unknown packet type {packet_type} from {addr}")

    def stop(self):
        self.running = False
        self.sock.close()
