from node import Node
from nameserver import NameServer
import time
import threading
import queue

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

# TODO: Fix NS Hello Packet handling and data route updates to nodes
# Implement handling of interest for routing
# When data is sent back by a node, the node will add it into its CS and FIB (not sure if this was done yet)

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
    for node in nodes:
        # NameServers and Nodes both implement load_neighbors_from_file
        try:
            node.load_neighbors_from_file("neighbors.txt")
        except Exception:
            pass
    time.sleep(2)

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

    # Test Case if within ADMU domain
    # interest_name = "/ADMU/hello.txt"
    # admu.add_cs(interest_name, "Hello from ADMU!")
    # send_interest_via_ns(acam1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case if within UP domain
    # interest_name = "/UP/hello.txt"
    # up.add_cs(interest_name, "Hello from UP!")
    # send_interest_via_ns(upc1, seq_num=0, name=interest_name, data_flag=False)

    # Test case for ADMU -> UP interdomain interests
    # interest_name = "/UP/Salcedo/PC1/hello.txt"
    # upc1.add_cs(interest_name, "Hello from upc1!")
    # send_interest_via_ns(acam1, seq_num=0, name=interest_name, data_flag=False)

    # START HERE FOR DEMO

    # Test Case if interest is localized in the DLSU domain
    interest_name = "/DLSU/Miguel/cam1/hello.txt"
    dcam1.add_cs(interest_name, "Hello from cam1")
    send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case to check the presence of a file in the CS (intradomain)
    # interest_name = "/DLSU/Miguel/cam1/hello.txt"
    # dcam1.add_cs(interest_name, "Hello from cam1")
    # send_interest_via_ns(andrew, seq_num=0, name=interest_name, data_flag=False)
    # time.sleep(5)
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case to check the presence of a node in the PIT (intradomain)
    # interest_name = "/DLSU/Miguel/cam1/hello.txt"
    # dcam1.add_cs(interest_name, "Hello from cam1")
    # send_interest_via_ns(andrew, seq_num=0, name=interest_name, data_flag=False)
    # time.sleep(5)
    # interest_name = "/DLSU/Miguel/cam1/hi.txt"
    # dcam1.add_cs(interest_name, "Hi from cam1")
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case if interest is in an adjacent domain (DLSU->ADMU)
    # interest_name = "/ADMU/Gonzaga/cam1/hello.txt"
    # acam1.add_cs(interest_name, "Hello from acam")
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case to check the presence of a file in the CS (interdomain)
    # interest_name = "/ADMU/Gonzaga/cam1/hello.txt"
    # acam1.add_cs(interest_name, "Hello from acam")
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)
    # time.sleep(5)
    # send_interest_via_ns(dcam1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case if interest is in a non-adjacent domain (DLSU->UP)
    # interest_name = "/UP/Salcedo/PC1/hello.txt"
    # upc1.add_cs(interest_name, "Hello from upc1")
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case if destination does not exist
    # interest_name = "/DLSU/Miguel/cam2/nothing_here.txt"
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    # Test Case if destination exists but file does not
    # interest_name = "/DLSU/Miguel/cam1/nothing_here.txt"
    # send_interest_via_ns(goks, seq_num=0, name=interest_name, data_flag=False)
    
    # Test case if destination does not have a filename
    # interest_name = "/DLSU/Miguel/cam1"
    # send_interest_via_ns(dpc1, seq_num=0, name=interest_name, data_flag=False)

    time.sleep(3)

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
LogGUI(controller).run()
