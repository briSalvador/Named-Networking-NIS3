from Packet import Packet

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class RouteDataPacket(Packet):
    def __init__(self, seq_num, name, routing_info, flags=0x0, timestamp=None):
        super().__init__(ROUTING_DATA, flags, seq_num, timestamp)
        self.name = name
        self.name_bytes = name.encode("utf-8")
        self.name_length = len(self.name_bytes)
        self.routing_info = routing_info
        if isinstance(routing_info, str):
            self.routing_info_bytes = routing_info.encode("utf-8")
        else:
            self.routing_info_bytes = routing_info
        self.info_size = len(self.routing_info_bytes)

    def __repr__(self):
        return (f"<RouteDataPacket PacketType={self.packet_type} Flags={self.flags} "
                f"SequenceNumber={self.seq_num} InfoSize={self.info_size} "
                f"NameLength={self.name_length} Name={self.name} "
                f"RoutingInfo={self.routing_info} Timestamp={self.timestamp}>")