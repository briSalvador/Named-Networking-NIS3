from node import Node
import time

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

# TODO: Set up initialize code to set up nodes, neighbors, and CS (did a bit of this)
# Make border router nodes be able to have multiple names

if __name__ == "__main__":
    pc1 = Node("/DLSU/Andrew/PC1", port=5001)
    andrew = Node("/DLSU/Andrew", port=5002)
    goks = Node("/DLSU/Gokongwei", port=5003)
    henry = Node("/DLSU/Henry", port=5004)
    dlsu = Node("/DLSU", port=5005)
    miguel = Node("/DLSU/Miguel", port=5006)
    cam1 = Node("/DLSU/Miguel/cam1", port=5007)

    nodes =[pc1, andrew, goks, henry, dlsu, miguel, cam1]

    # load all nodes
    for node in nodes:
        node.load_neighbors_from_file("neighbors.txt")

    # NodeA sends interest to NodeB
    """ nodeB.add_cs("sensor/data", "Temperature: 28C")
    nodeC.add_cs("sensor/data", "Temperature: 28C") """

    # NodeA -> NodeB, NodeB -> NodeC
    """ nodeA.add_fib("sensor/data", 5002, 30)
    nodeB.add_fib("sensor/data", 5003, 30) """

    pc1.send_interest(seq_num=1, name="sensor/data", flags=ACK_FLAG, target=("127.0.0.1", 5002))

    time.sleep(2)

    # neighbor tables
    print("\n--- Neighbor Tables ---")
    print("NodeA neighbors:", pc1.get_neighbors())
    print("NodeB neighbors:", andrew.get_neighbors())
    print("NodeC neighbors:", henry.get_neighbors())

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for node in nodes:
            node.stop()
