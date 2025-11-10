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
    dxa = Node("/DLSU/Router1 /ADMU/Router1", port=5008)
    gonzaga = Node("/ADMU/Gonzaga", port=6001)
    admu = Node("/ADMU", port=6002)
    acam1 = Node("/ADMU/Gonzaga/cam1", port=6003)
    kostka = Node("/ADMU/Kostka", port=6004)
    axu = Node("/ADMU/Router2 /UP/Router1", port=6005)
    up = Node("/UP", port=7001)
    salcedo = Node("/UP/Salcedo", port=7002)
    lara = Node("/UP/Lara", port=7003)
    upc1 = Node("/UP/Salcedo/PC1", port=7004)

    nodes =[dpc1, andrew, goks, henry, dlsu, miguel, dcam1, dxa, 
            gonzaga, admu, acam1, kostka, axu, up, salcedo, lara, upc1, ns, admu_ns]

    # load all nodes
    for node in nodes:
        # NameServers and Nodes both implement load_neighbors_from_file
        try:
            node.load_neighbors_from_file("neighbors.txt")
        except Exception:
            pass
    time.sleep(2)

    # neighbor tables
    print("\n--- Neighbor Tables ---")
    print("dpc1 neighbors:", dpc1.get_neighbors())
    print("andrew neighbors:", andrew.get_neighbors())
    print("henry neighbors:", henry.get_neighbors())
    print("border router neighbors: ", dxa.get_neighbors())
    print("NameServer neighbors:", ns.get_neigbors())


    # tests buffer and queueing (temp)
    NPU = 8
    TOTAL_PACKETS = 50 
    threads = []

    print(f"\n[TEST] Starting Buffer and Queueing Test...")
    print(f"[CONFIG] NPU = {NPU}, Total Packets = {TOTAL_PACKETS}\n")

    def send_fake_interest(i):
        processing_unit = i % NPU
        fake_name = f"/UP/UnknownTarget{processing_unit}"
        seq_num = 1000 + i
        andrew.send_interest(seq_num, fake_name, target=("127.0.0.1", 5005))
        print(f"[TEST] Packet {i} handled by NPU {processing_unit}")

    for i in range(TOTAL_PACKETS):
        t = threading.Thread(target=send_fake_interest, args=(i,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[TEST] Sent {TOTAL_PACKETS} Interest packets distributed across {NPU} NPUs.")
    print("[TEST] Buffer growth and FIFO processing sequence below...\n")

    time.sleep(4)

    # Interest Testing (Levenshtein Distance)
    dpc1.send_interest(seq_num=0, name="/DLSU/Henry/hello.txt", target=("127.0.0.1", 5001), data_flag=False)
    henry.add_cs("/DLSU/Henry/hello.txt", "Hello from henry!")
    # dpc1.send_interest(seq_num=0, name="/ADMU/Gonzaga/cam1/hello.txt", target=("127.0.0.1", 5001), data_flag=False)
    # acam1.add_cs("/ADMU/Gonzaga/cam1/hello.txt", "Hello from acam!")
    """ dcam1.add_cs("/DLSU/Miguel/cam1/hello.txt", "This is hello")
    miguel.add_cs("/DLSU/Miguel/cam1/hello.txt", "This is hello")
    goks.send_interest(seq_num=0, name="/DLSU/Miguel/cam1/nothing_here.txt", target=("127.0.0.1", 5004))
    goks.send_interest(seq_num=0, name="/DLSU/Miguel/cam1/hello.txt", target=("127.0.0.1", 5004)) """
    #henry.send_interest(seq_num=0, name="/DLSU/Andrew", target=("127.0.0.1", 5006))
    time.sleep(2)

    # fib tables
    print("\n--- FIB Tables ---")
    print("henry FIB:", henry.fib)
    print("dpc1 FIB:", dpc1.fib)
    print("dlsu FIB:", dlsu.fib)
    print("border router FIB: ", dxa.fib)

    print("\n--- PIT Tables ---")
    print("henry PIT:", henry.pit)
    print("miguel PIT: ", miguel.pit)
    print("dlsu PIT:", dlsu.pit)

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
        else:
            print(f"[DEBUG] Node {node_name} not found.")

    def run_test(self, test_id):
        print(f"[DEBUG] Running test case {test_id}...")
        # test
        if test_id == "1":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dest = self.nodes.get("/DLSU")
            if src and dest:
                src.send_interest(seq_num=1, name="sensor/data", target=("127.0.0.1", dest.port))
        else:
            print(f"[DEBUG] Test {test_id} not defined.")

    def help(self):
        print("""
[DEBUG COMMANDS]
  list                 - show all nodes
  select <node_name>   - zoom into a node (for later)
  run <test_id>        - execute a predefined test (run 1 for now)
  help                 - show this menu
  exit                 - quit debugging
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


controller = DebugController(nodes)

input_thread = threading.Thread(target=debug_input_loop, args=(controller,), daemon=True)
input_thread.start()


# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for node in nodes:
        node.stop()
