from node import Node
from nameserver import NameServer
import time
import threading
import queue
from datetime import datetime

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6
ROUTE_ACK = 0x7

# Flag Masks (lower 4 bits)
ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

# Statistics tracking class
class NetworkStatistics:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_counts = {
            'INTEREST': 0,
            'INTEREST_QUERY': 0,
            'DATA': 0,
            'ROUTING_DATA': 0,
            'HELLO': 0,
            'UPDATE': 0,
            'ERROR': 0,
            'ROUTE_ACK': 0
        }
        self.total_data_bits_transferred = 0
        self.total_hops = 0
        self.interest_data_pairs = {}  # {(origin, name, seq): {'interest_time': ts, 'data_time': ts}}
        # start_time is set when the phase actually begins
        self.start_time = None
        self.end_time = None
    
    def record_interest(self, origin_node, name, seq_num, timestamp):
        """Record when an interest packet is sent"""
        with self.lock:
            key = (origin_node, name, seq_num)
            if key not in self.interest_data_pairs:
                self.interest_data_pairs[key] = {}
            self.interest_data_pairs[key]['interest_time'] = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
            self.packet_counts['INTEREST'] += 1

    def record_interest_hop(self, origin_node, name, seq_num, node_name):
        """Append a node to the interest path for the given interest key."""
        with self.lock:
            key = (origin_node, name, seq_num)
            if key not in self.interest_data_pairs:
                self.interest_data_pairs[key] = {}
            path = self.interest_data_pairs[key].setdefault('interest_path', [])
            path.append(node_name)
    
    def record_interest_query(self):
        """Record when an interest query (data_flag=False) is sent to NameServer"""
        with self.lock:
            self.packet_counts['INTEREST_QUERY'] += 1
    
    def record_data(self, name, seq_num, payload_size, timestamp):
        """Record when a data packet is received and match it with interest"""
        with self.lock:
            # First, count the DATA packet
            self.packet_counts['DATA'] += 1
            self.total_data_bits_transferred += payload_size * 8  # Convert bytes to bits
            
            # Try to find and update matching interest records
            # Data packets may come from any origin, so we search for matching name and seq
            timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
            
            for key, times in self.interest_data_pairs.items():
                origin_node, interest_name, interest_seq = key
                # Match by name and sequence number (origin may differ for intermediate nodes)
                if interest_name == name and interest_seq == seq_num:
                    if 'interest_time' in times:
                        times['data_time'] = timestamp_dt

    def record_data_hop(self, name, seq_num, node_name):
        """(removed) previously used to append nodes to a separate data path."""
        # Deprecated: data path tracking removed — keep stub for compatibility.
        return

    
    def record_packet(self, packet_type, size_bits=0, size_bytes=0):
        """Record any packet type (but skip DATA/INTEREST as they're counted separately)"""
        with self.lock:
            packet_names = {
                INTEREST: 'INTEREST',
                DATA: 'DATA',
                ROUTING_DATA: 'ROUTING_DATA',
                HELLO: 'HELLO',
                UPDATE: 'UPDATE',
                ERROR: 'ERROR',
                ROUTE_ACK: 'ROUTE_ACK'
            }
            if packet_type in packet_names:
                packet_name = packet_names[packet_type]
                # Skip double-counting DATA and INTEREST (recorded separately)
                if packet_name not in ['DATA', 'INTEREST', 'HELLO', 'UPDATE']:
                    self.packet_counts[packet_name] += 1
                    # Track routing data bytes
                    if packet_name == 'ROUTING_DATA' and size_bytes > 0:
                        self.total_routing_bytes_transferred += size_bytes

    def record_hello(self):
        with self.lock:
            self.packet_counts['HELLO'] += 1
    
    def record_update(self):
        with self.lock:
            self.packet_counts['UPDATE'] += 1
    
    def record_hop(self):
        """Record a hop when a node receives a non-HELLO/UPDATE packet"""
        with self.lock:
            self.total_hops += 1
    
    def finalize(self):
        """Mark the end of statistics collection"""
        self.end_time = datetime.now()
    
    def calculate_latencies(self):
        """Calculate latency for each completed interest-data pair"""
        latencies = []
        with self.lock:
            for key, times in self.interest_data_pairs.items():
                if 'interest_time' in times and 'data_time' in times:
                    latency = (times['data_time'] - times['interest_time']).total_seconds()
                    latencies.append(latency)
        return latencies
    
    def get_statistics(self):
        """Get comprehensive network statistics"""
        total_time = ((self.end_time - self.start_time).total_seconds() if (self.start_time and self.end_time) else 0)
        latencies = self.calculate_latencies()
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        
        # Calculate throughput in bits per second
        throughput_bps = self.total_data_bits_transferred / total_time if total_time > 0 else 0
        throughput_kbps = throughput_bps / 1000
        
        # Count control packets (non-data)
        control_packets = (self.packet_counts['ROUTING_DATA'] +
                          self.packet_counts['ERROR'] +
                          self.packet_counts['HELLO'] + 
                          self.packet_counts['UPDATE'] + 
                          self.packet_counts['ROUTE_ACK'] +
                          self.packet_counts['INTEREST_QUERY'])
        
        total_packets = sum(self.packet_counts.values())
        control_overhead_percent = (control_packets / total_packets * 100) if total_packets > 0 else 0
        
        return {
            'total_time': total_time,
            'packet_counts': self.packet_counts,
            'total_packets': total_packets,
            'total_data_bits': self.total_data_bits_transferred,
            'total_hops': self.total_hops,
            'throughput_bps': throughput_bps,
            'throughput_kbps': throughput_kbps,
            'avg_latency_ms': avg_latency * 1000,
            'max_latency_ms': max_latency * 1000,
            'min_latency_ms': min_latency * 1000,
            'control_packets': control_packets,
            'control_overhead_percent': control_overhead_percent,
            'completed_pairs': len(latencies)
        }

# Global statistics instance
class PhaseAwareStats:
    """A wrapper that maintains separate NetworkStatistics objects for
    different phases and delegates recording to the active phase.
    """
    def __init__(self, phase_names=None, default_phase=None):
        phase_names = phase_names or ["initialization", "first_request", "second_request"]
        self.phases = {name: NetworkStatistics() for name in phase_names}
        self.active = default_phase or phase_names[0]
        # mark the active phase start time when stats object is created
        try:
            self.phases[self.active].start_time = datetime.now()
        except Exception:
            pass

    def set_phase(self, phase_name):
        # End previous active phase (if it was started and not yet ended)
        try:
            prev = self.active
            if prev in self.phases:
                prev_st = self.phases[prev]
                if prev_st.start_time is not None and prev_st.end_time is None:
                    prev_st.end_time = datetime.now()
        except Exception:
            pass

        if phase_name not in self.phases:
            self.phases[phase_name] = NetworkStatistics()
        self.active = phase_name
        st = self.phases[phase_name]
        # (re)start the phase timer when the phase is set
        st.start_time = datetime.now()
        st.end_time = None

    def _active(self):
        return self.phases[self.active]

    @property
    def interest_data_pairs(self):
        combined = {}
        for st in self.phases.values():
            if hasattr(st, 'interest_data_pairs') and isinstance(st.interest_data_pairs, dict):
                combined.update(st.interest_data_pairs)
        return combined

    # Delegate methods
    def record_interest(self, origin_node, name, seq_num, timestamp):
        return self._active().record_interest(origin_node, name, seq_num, timestamp)

    def record_interest_query(self):
        return self._active().record_interest_query()

    def record_data(self, name, seq_num, payload_size, timestamp):
        return self._active().record_data(name, seq_num, payload_size, timestamp)

    def record_packet(self, packet_type, size_bits=0, size_bytes=0):
        return self._active().record_packet(packet_type, size_bits=size_bits, size_bytes=size_bytes)

    def record_hop(self):
        return self._active().record_hop()

    def record_interest_hop(self, origin_node, name, seq_num, node_name):
        return self._active().record_interest_hop(origin_node, name, seq_num, node_name)
    

    # Delegate hello/update so nodes can record these directly
    def record_hello(self):
        return self._active().record_hello()

    def record_update(self):
        return self._active().record_update()

    def finalize(self):
        for st in self.phases.values():
            try:
                # only finalize phases that have been started
                if st.start_time is not None and st.end_time is None:
                    st.finalize()
            except Exception:
                pass

    def end_active_phase(self):
        """Explicitly end the currently active phase by setting its end_time."""
        try:
            st = self.phases.get(self.active)
            if st and st.start_time is not None and st.end_time is None:
                st.end_time = datetime.now()
        except Exception:
            pass

    def calculate_latencies(self, phase=None):
        if phase:
            return self.phases[phase].calculate_latencies()
        # aggregate
        latencies = []
        for st in self.phases.values():
            latencies.extend(st.calculate_latencies())
        return latencies

    def get_statistics(self, phase=None):
        # If a specific phase requested, return that phase's stats
        if phase:
            return self.phases[phase].get_statistics()

        # Otherwise return combined stats across all phases
        combined = {
            'total_time': 0,
            'packet_counts': {k: 0 for k in self._active().packet_counts.keys()},
            'total_packets': 0,
            'total_data_bits': 0,
            'total_hops': 0,
            'throughput_bps': 0,
            'throughput_kbps': 0,
            'avg_latency_ms': 0,
            'max_latency_ms': 0,
            'min_latency_ms': 0,
            'control_packets': 0,
            'control_overhead_percent': 0,
            'completed_pairs': 0
        }

        all_latencies = []
        for st in self.phases.values():
            s = st.get_statistics()
            combined['total_time'] += s['total_time']
            for k, v in s['packet_counts'].items():
                combined['packet_counts'][k] = combined['packet_counts'].get(k, 0) + v
            combined['total_packets'] += s['total_packets']
            combined['total_data_bits'] += s['total_data_bits']
            combined['total_hops'] += s['total_hops']
            combined['control_packets'] += s['control_packets']
            all_latencies.extend(st.calculate_latencies())
            combined['completed_pairs'] += s.get('completed_pairs', 0)

        combined['avg_latency_ms'] = (sum(all_latencies) / len(all_latencies) * 1000) if all_latencies else 0
        combined['max_latency_ms'] = (max(all_latencies) * 1000) if all_latencies else 0
        combined['min_latency_ms'] = (min(all_latencies) * 1000) if all_latencies else 0
        combined['throughput_bps'] = combined['total_data_bits'] / (combined['avg_latency_ms'] / 1000) if combined['avg_latency_ms'] > 0 else 0
        combined['throughput_kbps'] = combined['throughput_bps'] / 1000
        combined['control_overhead_percent'] = (combined['control_packets'] / combined['total_packets'] * 100) if combined['total_packets'] > 0 else 0

        return combined


# Global phase-aware statistics instance
global_stats = PhaseAwareStats()

# Export for other modules
__all__ = ['global_stats', 'NetworkStatistics', 'DebugController']

if __name__ == "__main__":
    ns = NameServer(ns_name="/DLSU/NameServer1", host="127.0.0.1", port=5000, topo_file="DLSU_NameServer1_topology.txt")
    admu_ns = NameServer(ns_name="/ADMU/NameServer1", host="127.0.0.1", port=6000, topo_file="ADMU_NameServer1_topology.txt")
    up_ns = NameServer(ns_name="/UP/NameServer1", host="127.0.0.1", port=7000, topo_file="UP_NameServer1_topology.txt")
    
    dpc1 = Node("/DLSU/Andrew/PC1", port=5001)
    andrew = Node("/DLSU/Andrew", port=5002)
    goks = Node("/DLSU/Gokongwei", port=5003)
    henry = Node("/DLSU/Henry", port=5004)
    dlsu = Node("/DLSU", port=5005)
    miguel = Node("/DLSU/Miguel", port=5006)
    dcam1 = Node("/DLSU/Miguel/cam1", port=5007)
    dxa = Node("/DLSU/Router1 /ADMU/Router1", port=5008, isborder=True)
    gonzaga = Node("/ADMU/Gonzaga", port=6001)
    admu = Node("/ADMU", port=6002)
    acam1 = Node("/ADMU/Gonzaga/cam1", port=6003)
    kostka = Node("/ADMU/Kostka", port=6004)
    axu = Node("/ADMU/Router2 /UP/Router1", port=6005, isborder=True)
    up = Node("/UP", port=7001)
    salcedo = Node("/UP/Salcedo", port=7002)
    lara = Node("/UP/Lara", port=7003)
    upc1 = Node("/UP/Salcedo/PC1", port=7004)

    nodes =[dpc1, andrew, goks, henry, dlsu, miguel, dcam1, dxa, 
            gonzaga, admu, acam1, kostka, axu, up, salcedo, lara, upc1, ns, admu_ns, up_ns]

    # load all nodes
    # Start statistics phase for initialization (hello/topology)
    try:
        global_stats.set_phase("initialization")
    except Exception:
        pass

    for node in nodes:
        # NameServers and Nodes both implement load_neighbors_from_file
        try:
            node.load_neighbors_from_file("neighbors.txt")
        except Exception:
            pass
    # End initialization phase now that neighbor loading is complete
    try:
        global_stats.end_active_phase()
    except Exception:
        pass
    
    # keep a short pause for network stabilization, but do not count it in initialization
    time.sleep(1)

    # Start periodic HELLO / neighbor-file reload every 30 seconds.
    # This ensures NameServers and Nodes re-announce and re-learn neighbor ports.
    # def _periodic_hello_loop(all_nodes, interval=30):
    #     while True:
    #         for n in all_nodes:
    #             try:
    #                 # Both Node and NameServer implement load_neighbors_from_file
    #                 n.load_neighbors_from_file("neighbors.txt")
    #             except Exception:
    #                 # ignore per-node failures (keep loop running)
    #                 pass
    #             # If a Node exposes a neighbor-discovery loop, start it once (daemon)
    #             try:
    #                 if hasattr(n, "start_neighbor_discovery") and callable(getattr(n, "start_neighbor_discovery")):
    #                     # start_neighbor_discovery returns a thread; avoid starting multiple times
    #                     if not getattr(n, "_neighbor_discovery_started", False):
    #                         try:
    #                             n.start_neighbor_discovery(interval=interval)
    #                         except Exception:
    #                             pass
    #                         n._neighbor_discovery_started = True
    #             except Exception:
    #                 pass
    #         time.sleep(interval)

    # hello_thread = threading.Thread(target=_periodic_hello_loop, args=(nodes, 30), daemon=True)
    # hello_thread.start()

    # neighbor tables
    # print("\n--- Neighbor Tables ---")
    # print("dpc1 neighbors:", dpc1.get_neighbors())
    # print("andrew neighbors:", andrew.get_neighbors())
    # print("henry neighbors:", henry.get_neighbors())
    # print("border router neighbors: ", dxa.get_neighbors())
    # print("NameServer neighbors:", ns.get_neigbors())

    # tests buffer and queueing (temp)
    # NPU = 8
    # TOTAL_PACKETS = 50 
    # threads = []

    # print(f"\n[TEST] Starting Buffer and Queueing Test...")
    # print(f"[CONFIG] NPU = {NPU}, Total Packets = {TOTAL_PACKETS}\n")

    # def send_fake_interest(i):
    #     processing_unit = i % NPU
    #     fake_name = f"/UP/UnknownTarget{processing_unit}"
    #     seq_num = 1000 + i
    #     andrew.send_interest(seq_num, fake_name, target=("127.0.0.1", 5003))
    #     print(f"[TEST] Packet {i} handled by NPU {processing_unit}")

    # for i in range(TOTAL_PACKETS):
    #     t = threading.Thread(target=send_fake_interest, args=(i,))
    #     t.start()
    #     threads.append(t)

    # for t in threads:
    #     t.join()

    # print(f"\n[TEST] Sent {TOTAL_PACKETS} Interest packets distributed across {NPU} NPUs.")
    # print("[TEST] Buffer growth and FIFO processing sequence below...\n")

    # time.sleep(5)

    def _ns_for_origin(origin_node):
        """Return the NameServer object for origin based on its top-level domain."""
        try:
            origin_top = origin_node.name.strip('/').split('/', 1)[0]
        except Exception:
            origin_top = "DLSU"
        if origin_top == "DLSU":
            return ns
        if origin_top == "ADMU":
            return admu_ns
        if origin_top == "UP":
            return up_ns
        return ns

    def send_interest_via_ns(origin_node, seq_num, name, data_flag=False):
        """Send an Interest from origin_node toward the NameServer of its domain,
        but actually send to the first-hop neighbor toward that NameServer.
        """
        ns_obj = _ns_for_origin(origin_node)
        target = ("127.0.0.1", ns_obj.port)  # fallback: direct to NS
        try:
            path = ns_obj._shortest_path(origin_node.name, ns_obj.ns_name)
            if path and len(path) > 1:
                first_hop = path[1]
                # prefer origin's own mapping, then NS mapping, then alias splits
                port = None
                if hasattr(origin_node, "name_to_port"):
                    port = origin_node.name_to_port.get(first_hop)
                if not port and hasattr(ns_obj, "name_to_port"):
                    port = ns_obj.name_to_port.get(first_hop)
                if not port:
                    # try alias tokens
                    for candidate in (first_hop.split() if isinstance(first_hop, str) else []):
                        if hasattr(origin_node, "name_to_port") and candidate in origin_node.name_to_port:
                            port = origin_node.name_to_port[candidate]
                            break
                        if hasattr(ns_obj, "name_to_port") and candidate in ns_obj.name_to_port:
                            port = ns_obj.name_to_port[candidate]
                            break
                if port:
                    target = ("127.0.0.1", int(port))
        except Exception:
            # any failure: fall back to direct NS port (already set)
            pass

        origin_node.send_interest(seq_num=seq_num, name=name, target=target, data_flag=data_flag)

    # TEST CASE

    # 0 = dpc1
    # 1 = andrew
    # 2 = goks
    # 3 = henry
    # 4 = dlsu
    # 5 = miguel
    # 6 = dcam1
    # 7 = dxa
    # 8 = gonzaga
    # 9 = admu
    # 10 = acam1
    # 11 = kostka
    # 12 = axu
    # 13 = up
    # 14 = salcedo
    # 15 = lara
    # 16 = upc1
    # 17 = ns
    # 18 = admu_ns
    # 19 = up_ns
    
    orig = nodes[3]
    dest = nodes[5]
    interest_name1 = "/DLSU/Miguel/data.txt"
    interest_name2 = "/DLSU/Miguel/info.txt"
    msg1 = "Hello from dest1"
    msg2 = "Hello from dest2"

    dest.add_cs(interest_name1, msg1)
    # switch to first-request phase
    try:
        global_stats.set_phase("first_request")
    except Exception:
        pass
    send_interest_via_ns(orig, seq_num=0, name=interest_name1, data_flag=False)
    
    # Wait until node has received the data packet
    max_wait_time = 10  # seconds
    start_time = time.time()
    while not orig.has_received_data(interest_name1):
        if time.time() - start_time > max_wait_time:
            print(f"[WARNING] Timeout waiting for {orig.name} to receive data for {interest_name1}")
            break
        time.sleep(0.001)

    dest.add_cs(interest_name2, msg2)

    # Reset the received data status before sending again
    orig.reset_received_data(interest_name2)

    # switch to second-request phase
    try:
        global_stats.set_phase("second_request")
    except Exception:
        pass
    send_interest_via_ns(orig, seq_num=0, name=interest_name2, data_flag=False)

    max_wait_time = 10  # seconds
    start_time = time.time()
    while not orig.has_received_data(interest_name2):
        if time.time() - start_time > max_wait_time:
            print(f"[WARNING] Timeout waiting for {orig.name} to receive data for {interest_name2}")
            break
        time.sleep(0.001)

""" # destination does not exist
print("\n[TEST] Testing error case: destination does not exist")
error_origin = nodes[0]
error_interest_name = "/DLSU/Miguel/cam2/nothing_here.txt"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin, seq_num=0, name=error_interest_name, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin.has_received_data(error_interest_name):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name} (expected - destination doesn't exist)")
        break
    time.sleep(0.1)

# destination exists but file does not
print("\n[TEST] Testing error case: destination exists but file does not")
error_origin2 = nodes[2]
error_interest_name2 = "/DLSU/Miguel/cam1/nothing_here.txt"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin2, seq_num=0, name=error_interest_name2, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin2.has_received_data(error_interest_name2):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name2} (expected - file doesn't exist at destination)")
        break
    time.sleep(0.1) """
    
"""
# destination does not have a filename
print("\n[TEST] Testing error case: destination does not have a filename")
error_origin3 = nodes[0]
error_interest_name3 = "/DLSU/Miguel/cam1"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin3, seq_num=0, name=error_interest_name3, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin3.has_received_data(error_interest_name3):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name3} (expected - no filename provided)")
        break
    time.sleep(0.1)
"""
    # fib tables
    # print("\n--- FIB Tables ---")
    # print("dpc1 FIB:", dpc1.fib)
    # print("andrew FIB:", andrew.fib)
    # print("goks FIB: ", goks.fib)
    # print("henry FIB:", henry.fib)
    # print("dlsu FIB:", dlsu.fib)
    # print("dcam1 FIB", dcam1.fib)
    # print("border router FIB: ", dxa.fib)
    # print("admu FIB: ", admu.fib)
    # print("gonzaga FIB: ", gonzaga.fib)
    # print("acam1 FIB", acam1.fib)
    # print("salcedo FIB", salcedo.fib)

    # print("\n--- PIT Tables ---")
    # print("henry PIT:", henry.pit)
    # print("miguel PIT: ", miguel.pit)
    # print("dlsu PIT:", dlsu.pit)
    # print("goks PIT:", goks.pit)

# DEBUGGING MENU 
class DebugController:
    def print_sorted_logs(self, node_names):
        selected_nodes = [self.nodes[name] for name in node_names if name in self.nodes]
        all_logs = []
        for node in selected_nodes:
            for entry in getattr(node, 'logs', []):
                all_logs.append({"node": getattr(node, 'name', getattr(node, 'ns_name', 'Unknown')), "timestamp": entry["timestamp"], "message": entry["message"]})
        all_logs.sort(key=lambda x: x["timestamp"])
        for log in all_logs:
            print(f"[{log['timestamp']}]: {log['message']}")

    def __init__(self, nodes):
        self.nodes = {}
        for n in nodes:
            if hasattr(n, "name"):
                self.nodes[n.name] = n
            elif hasattr(n, "ns_name"):
                self.nodes[n.ns_name] = n
        self.selected_node = None
        self.command_queue = queue.Queue()


    def list_nodes(self):
        print("\nAvailable Nodes:")
        for n in self.nodes.values():
            node_name = getattr(n, "name", getattr(n, "ns_name", "Unknown"))
            node_port = getattr(n, "port", "N/A")
            print(f"  {node_name}  (port {node_port})")
        print()


    def select_node(self, node_name):
        if node_name in self.nodes:
            self.selected_node = self.nodes[node_name]
            print(f"\n[DEBUG] Zoomed into node: {node_name} (port {self.selected_node.port})")
            if hasattr(self.selected_node, "ns_name"):
                nameserver_debug_menu(self.selected_node)
            else:
                node_debug_menu(self.selected_node)
        else:
            print(f"[DEBUG] Node {node_name} not found.")

    def send_interest(self, origin_name, interest_name, seq_num=0):
        origin = self.nodes.get(origin_name)
        if not origin:
            print(f"[DEBUG] Origin node {origin_name} not found.")
            return

        try:
            send_interest_via_ns(
                origin_node=origin,
                seq_num=seq_num,
                name=interest_name,
                data_flag=False
            )
            print(f"[DEBUG] Sent INTEREST from {origin_name} for {interest_name} (seq={seq_num})")
        except Exception as e:
            print(f"[DEBUG] Failed to send INTEREST: {e}")

    def add_cs(self, node_name, content_name, data_value):
        node = self.nodes.get(node_name)
        if not node:
            print(f"[DEBUG] Node {node_name} not found.")
            return

        try:
            if hasattr(node, "add_cs") and callable(getattr(node, "add_cs")):
                node.add_cs(content_name, data_value)
            else:
                if not hasattr(node, "cs"):
                    node.cs = {}
                node.cs[content_name] = data_value
            print(f"[DEBUG] Added CS entry on {node_name}: {content_name} -> {data_value}")
        except Exception as e:
            print(f"[DEBUG] Failed to add CS entry: {e}")

    def run_test(self, test_id):
        print(f"[DEBUG] Running test case {test_id}...")

        # intra-domain
        if test_id == "1":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dest = self.nodes.get("/DLSU/Gokongwei")
            if src and dest:
                print("[TEST 1] Sending Interest within DLSU domain...")
                # not sure yet
                try:
                    dest.add_cs("/DLSU/Gokongwei/hello.txt", "Hello from Gokongwei!")
                except Exception:
                    pass
                src.send_interest(
                    seq_num=1,
                    name="/DLSU/Gokongwei/hello.txt",
                    target=("127.0.0.1", dest.port),
                )
            else:
                print("[TEST 1] Nodes not found in registry.")

        # inter-domain
        elif test_id == "2":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dest = self.nodes.get("/UP/Salcedo/PC1")
            if src and dest:
                print("[TEST 2] Sending Interest across domains (DLSU → UP)...")
                try:
                    dest.add_cs("/UP/Salcedo/PC1/status.txt", "UP Salcedo PC1 is alive")
                except Exception:
                    pass
                src.send_interest(
                    seq_num=10,
                    name="/UP/Salcedo/PC1/status.txt",
                    target=("127.0.0.1", dest.port),
                )
            else:
                print("[TEST 2] Source or destination node not found.")

        # nonexistent node (domain exists)
        elif test_id == "3":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            admu_ns = self.nodes.get("/ADMU/NameServer1")
            if src and admu_ns:
                print("[TEST 3] Sending Interest to nonexistent node in ADMU...")
                src.send_interest(
                    seq_num=20,
                    name="/ADMU/nonexistent_node/hello.pdf",
                    target=("127.0.0.1", admu_ns.port),
                )
            else:
                print("[TEST 3] Source node or ADMU NameServer not found.")

        # nonexistent domain
        elif test_id == "4":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dlsu_ns = self.nodes.get("/DLSU/NameServer1")
            if src and dlsu_ns:
                print("[TEST 4] Sending Interest to nonexistent domain /XYZ...")
                src.send_interest(
                    seq_num=30,
                    name="/XYZ/UnknownNode/data.txt",
                    target=("127.0.0.1", dlsu_ns.port),
                )
            else:
                print("[TEST 4] Source node or DLSU NameServer not found.")

        # malformed packet
        elif test_id == "5":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            if src:
                print("[TEST 5] Sending malformed packet...")
                import struct
                packet_type = 0x0
                flags = 0x0
                ptf = (packet_type << 4) | (flags & 0xF)
                seq = 0xAA
                name = b"bad"
                name_len = len(name)
                header = struct.pack("!BBB", ptf, seq, name_len)
                payload = header + name + b"\x03" + b"zzz"
                src.sock.sendto(payload, ("127.0.0.1", src.port))
            else:
                print("[TEST 5] Source node not found.")

        else:
            print(f"[DEBUG] Test {test_id} not defined. Use 1-5.")


    def help(self):
        print("""
[DEBUG COMMANDS]
  list                             - show all nodes
  select <node_name>               - zoom into a node
  run <test_id>                    - execute a test (1-5)
  addcs <node> <name> <data>       - add a CS entry
  interest <origin> <name> [seq]   - send Interest
  filter <names...>                - logs for listed nodes
  help                             - show this menu
  exit                             - quit debugging
        """)

    def process_command(self, cmd):
        parts = cmd.strip().split()
        if not parts:
            return False
        match parts[0]:
            case "list":
                self.list_nodes()
            case "select":
                if len(parts) > 1:
                    self.select_node(parts[1])
                else:
                    print("[DEBUG] Usage: select <node_name>")
            case "run":
                if len(parts) > 1:
                    self.run_test(parts[1])
                else:
                    print("[DEBUG] Usage: run <test_id>")
            case "interest":
                # interest <origin_node> <content_name> [seq]
                if len(parts) >= 3:
                    origin_name = parts[1]
                    interest_name = parts[2]
                    try:
                        seq_num = int(parts[3]) if len(parts) > 3 else 0
                    except ValueError:
                        print("[DEBUG] seq_num must be an integer; defaulting to 0.")
                        seq_num = 0
                    self.send_interest(origin_name, interest_name, seq_num)
                else:
                    print("[DEBUG] interest <origin_node_name> <content_name> [seq_num]")
            case "addcs":
                # addcs <node_name> <content_name> <data>
                if len(parts) >= 4:
                    node_name = parts[1]
                    content_name = parts[2]
                    data_value = " ".join(parts[3:])
                    self.add_cs(node_name, content_name, data_value)
                else:
                    print("[DEBUG] addcs <node_name> <content_name> <data>")
            case "help":
                self.help()
            case "exit":
                print("[DEBUG] Exiting debug input thread...")
                self.command_queue.put("exit")
                return True
            case "filter":
                if len(parts) > 1:
                    self.print_sorted_logs(parts[1:])
                else:
                    print("[DEBUG] Usage: filter <node_name> <node_name> ...")
            case _:
                print("[DEBUG] Unknown command. Type 'help' for options.")
        return False


def debug_input_loop(controller):
    controller.help()
    while True:
        cmd = input("> ")
        if controller.process_command(cmd):
            break


# node debug menu
def node_debug_menu(node):
    print(f"\nNode Name/s: {getattr(node, 'name', getattr(node, 'ns_name', 'Unknown'))}")
    print(f"Port: {getattr(node, 'port', 'N/A')}")
    print("[AVAILABLE COMMANDS]")
    print("  view fib")
    print("  view pit")
    print("  view cs")
    print("  view buffer")
    print("  view neighbors")
    print("  view logs")
    print("  back\n")

    while True:
        cmd = input(f"{getattr(node, 'name', 'Node')}> ").strip().lower()
        if cmd == "back":
            print("\n[DEBUG] Returning to global menu...\n")
            break

        elif cmd == "view fib":
            print(f"\n[FIB for {node.name}]")
            print(node.fib if hasattr(node, "fib") else "No FIB table.\n")

        elif cmd == "view pit":
            print(f"\n[PIT for {node.name}]")
            print(node.pit if hasattr(node, "pit") else "No PIT table.\n")

        elif cmd == "view cs":
            print(f"\n[CS for {node.name}]")
            print(node.cs if hasattr(node, 'cs') else "No CS cache.\n")

        elif cmd == "view buffer":
            print(f"\n[BUFFER for {node.name}]")
            if hasattr(node, "buffer"):
                for entry in node.buffer:
                    print(entry)
            else:
                print("No buffer.\n")

        elif cmd == "view neighbors":
            if hasattr(node, "get_neighbors"):
                print(f"\n[Neighbors of {node.name}]")
                print(node.get_neighbors())
            else:
                print("No neighbor table.\n")

        elif cmd == "view logs":
            if hasattr(node, "logs"):
                print(f"\n[Logs for {node.name}]")
                for log in node.logs:
                    print(f"[{log['timestamp']}] {log['message']}")
            else:
                print("No logs found.\n")

        else:
            print("[DEBUG] Unknown command. Type one of: view fib/pit/cs/buffer/neighbors/logs/back")

# nameserver debug menu
def nameserver_debug_menu(ns):
    print(f"\nNameServer: {getattr(ns, 'ns_name', 'Unknown')}")
    print(f"Port: {getattr(ns, 'port', 'N/A')}")
    print("[AVAILABLE COMMANDS]")
    print("  view fib")
    print("  view registry")
    print("  view neighbors")
    print("  back\n")

    while True:
        cmd = input(f"{getattr(ns, 'ns_name', 'NS')}> ").strip().lower()
        if cmd == "back":
            print("\n[DEBUG] Returning to global menu...\n")
            break

        elif cmd == "view fib":
            print(f"\n[FIB for {ns.ns_name}]")
            print(getattr(ns, "fib", "No FIB table.\n"))

        elif cmd == "view registry":
            reg = getattr(ns, "registry", getattr(ns, "registered_nodes", None))
            if reg:
                print(f"\n[Registry for {ns.ns_name}]")
                for name, info in reg.items():
                    print(f"  {name} → {info}")
            else:
                print("No registry or registered nodes.\n")

        elif cmd == "view neighbors":
            if hasattr(ns, "get_neigbors"):
                print(f"\n[Neighbors of {ns.ns_name}]")
                print(ns.get_neigbors())
            else:
                print("No neighbor table.\n")

        else:
            print("[DEBUG] Unknown command. Type one of: view fib/registry/neighbors/back")

controller = DebugController(nodes)

def print_network_statistics():
    """Print comprehensive network statistics"""
    # finalize and collect per-phase stats
    global_stats.finalize()
    phases = ["initialization", "first_request", "second_request"]
    phase_stats = {p: global_stats.get_statistics(p) for p in phases}
    combined = global_stats.get_statistics()

    print("\n" + "="*80)
    print("NETWORK PERFORMANCE STATISTICS (PER PHASE)")
    print("="*80)

    for p in phases:
        s = phase_stats[p]
        print(f"\n[PHASE] {p}")
        print(f"  Duration:           {s['total_time']:.3f} seconds")
        print(f"  Total Data Bits:    {s['total_data_bits']} bits")
        print(f"  Total Packets:      {s['total_packets']} packets")
        print(f"  INTEREST:           {s['packet_counts'].get('INTEREST', 0)}")
        print(f"  INTEREST_QUERY:     {s['packet_counts'].get('INTEREST_QUERY', 0)}")
        print(f"  DATA:               {s['packet_counts'].get('DATA', 0)}")
        print(f"  HELLO:              {s['packet_counts'].get('HELLO', 0)}")
        print(f"  UPDATE:             {s['packet_counts'].get('UPDATE', 0)}")
        print(f"  ROUTING_DATA:       {s['packet_counts'].get('ROUTING_DATA', 0)}")
        print(f"  ROUTE_ACK:          {s['packet_counts'].get('ROUTE_ACK', 0)}")
        print(f"  ERROR:              {s['packet_counts'].get('ERROR', 0)}")
        print(f"  Control Packets:    {s['control_packets']} ({s['control_overhead_percent']:.2f}% overhead)")
        print(f"  Avg Latency:        {s['avg_latency_ms']:.3f} ms")
        print(f"  Throughput:         {s['throughput_bps']:.3f} bps")
        print(f"  Total Hops:         {s['total_hops']} hops")
        print(f"  Completed Pairs:    {s.get('completed_pairs', 0)}")
        # Print paths for completed interest-data pairs in this phase
        try:
            st = global_stats.phases.get(p)
            if st and getattr(st, 'interest_data_pairs', None):
                for key, info in st.interest_data_pairs.items():
                    # only show completed pairs
                    if 'interest_time' in info and 'data_time' in info:
                        ipath = info.get('interest_path', [])
                        print(f"  Interest/Data path: {ipath}")
        except Exception:
            pass

    print("\n" + "="*80)
    print("NETWORK PERFORMANCE STATISTICS (COMBINED)")
    print("="*80)

    print("\n[LATENCY METRICS]")
    print(f"  Average Latency:        {combined['avg_latency_ms']:.3f} ms")
    print(f"  Maximum Latency:        {combined['max_latency_ms']:.3f} ms")
    print(f"  Minimum Latency:        {combined['min_latency_ms']:.3f} ms")
    print(f"  Completed Interest-Data Pairs: {combined['completed_pairs']}")

    print("\n[THROUGHPUT METRICS]")
    print(f"  Total Data Transmitted: {combined['total_data_bits']} bits ({combined['total_data_bits']/8:.1f} bytes)")
    print(f"  Throughput:             {combined['throughput_bps']:.2f} bps ({combined['throughput_kbps']:.3f} kbps)")
    print(f"  Test Duration:          {combined['total_time']:.3f} seconds")

    print("\n[PACKET TRANSMISSION OVERHEAD]")
    print(f"  Total Packets Sent:     {combined['total_packets']} packets")
    print(f"    - INTEREST packets:   {combined['packet_counts'].get('INTEREST', 0)}")
    print(f"    - INTEREST_QUERY packets: {combined['packet_counts'].get('INTEREST_QUERY', 0)}")
    print(f"    - DATA packets:       {combined['packet_counts'].get('DATA', 0)}")
    print(f"    - ROUTING_DATA:       {combined['packet_counts'].get('ROUTING_DATA', 0)}")
    print(f"    - HELLO packets:      {combined['packet_counts'].get('HELLO', 0)}")
    print(f"    - UPDATE packets:     {combined['packet_counts'].get('UPDATE', 0)}")
    print(f"    - ERROR packets:      {combined['packet_counts'].get('ERROR', 0)}")
    print(f"    - ROUTE_ACK packets:  {combined['packet_counts'].get('ROUTE_ACK', 0)}")

    print("\n[CONTROL OVERHEAD]")
    print(f"  Control Packets:        {combined['control_packets']} packets")
    print(f"  Control Overhead:       {combined['control_overhead_percent']:.2f}%")
    print(f"  Data Packet Ratio:      {100 - combined['control_overhead_percent']:.2f}%")

    print("\n[ROUTING HOPS]")
    print(f"  Total Hops:             {combined['total_hops']} hops")

    print("\n" + "="*80)

"""
input_thread = threading.Thread(target=debug_input_loop, args=(controller,), daemon=True)
input_thread.start()


# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for node in nodes:
        node.stop()
"""
from gui import LogGUI

# Print statistics before starting GUI
print_network_statistics()

LogGUI(controller).run()
