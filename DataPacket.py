from Packet import Packet

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class DataPacket(Packet):
    def __init__(self, seq_num, name, payload, flags=0x0, timestamp=None):
        super().__init__(DATA, flags, seq_num, timestamp)
        self.name = name
        self.name_length = len(name.encode("utf-8"))
        self.payload = payload
        self.payload_size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)

    def __repr__(self):
        return (f"<DataPacket PacketType={self.packet_type} Flags={self.flags} "
                f"SequenceNumber={self.seq_num} PayloadSize={self.payload_size} "
                f"NameLength={self.name_length} Name={self.name} "
                f"Payload={self.payload} Timestamp={self.timestamp}>")