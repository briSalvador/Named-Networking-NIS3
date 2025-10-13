from node import Node
from nameserver import NameServer
import time
import threading

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
    ns = NameServer(ns_name="/DLSU/NameServer1", host="127.0.0.1", port=5000, topo_file="topology.txt")
    admu_ns = NameServer(ns_name="/ADMU/NameServer1", host="127.0.0.1", port=6000, topo_file="topology.txt")
    
    dpc1 = Node("/DLSU/Andrew/PC1", port=5001)
    andrew = Node("/DLSU/Andrew", port=5002)
    goks = Node("/DLSU/Gokongwei", port=5003)
    henry = Node("/DLSU/Henry", port=5004)
    dlsu = Node("/DLSU", port=5005)
    miguel = Node("/DLSU/Miguel", port=5006)
    dcam1 = Node("/DLSU/Miguel/cam1", port=5007)
    dxa = Node("/DLSU/Router1 /ADMU/Router1", port=5008)
    gonzaga = Node("/ADMU/Gonzaga", port=5009)
    admu = Node("/ADMU", port=5010)
    acam1 = Node("/ADMU/Gonzaga/cam1", port=5011)
    kostka = Node("/ADMU/Kostka", port=5012)
    axu = Node("/ADMU/Router2 /UP/Router1", port=5013)
    up = Node("/UP", port=5014)
    salcedo = Node("/UP/Salcedo", port=5015)
    lara = Node("/UP/Lara", port=5016)
    upc1 = Node("/UP/Salcedo/PC1", port=5017)

    nodes =[dpc1, andrew, goks, henry, dlsu, miguel, dcam1, dxa, 
            gonzaga, admu, acam1, kostka, axu, up, salcedo, lara, upc1, ns, admu_ns]

    # load all nodes
    for node in nodes:
        node.load_neighbors_from_file("neighbors.txt")

    dpc1.send_interest(seq_num=1, name="sensor/data", flags=ACK_FLAG, target=("127.0.0.1", 5002))

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


    time.sleep(10)

    # fib tables
    print("\n--- FIB Tables ---")
    print("dpc1 FIB:", dpc1.fib)
    print("border router FIB: ", dxa.fib)

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for node in nodes:
            node.stop()
