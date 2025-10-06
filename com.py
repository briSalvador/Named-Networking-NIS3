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
    dpc1 = Node("/DLSU/Andrew/PC1", port=5001)
    andrew = Node("/DLSU/Andrew", port=5002)
    goks = Node("/DLSU/Gokongwei", port=5003)
    henry = Node("/DLSU/Henry", port=5004)
    dlsu = Node("/DLSU", port=5005)
    miguel = Node("/DLSU/Miguel", port=5006)
    dcam1 = Node("/DLSU/Miguel/cam1", port=5007)
    dxa = Node("/DLSU/Router1", port=5008)
    gonzaga = Node("/ADMU/Gonzaga", port=5009)
    admu = Node("/ADMU", port=5010)
    acam1 = Node("/ADMU/Gonzaga/cam1", port=5011)
    kostka = Node("/ADMU/Kostka", port=5012)
    axu = Node("/ADMU/Router2", port=5013)
    up = Node("/UP", port=5014)
    salcedo = Node("/UP/Salcedo", port=5015)
    lara = Node("/UP/Lara", port=5016)
    upc1 = Node("/UP/Salcedo/PC1", port=5017)


    nodes =[dpc1, andrew, goks, henry, dlsu, miguel, dcam1, dxa, gonzaga, admu, acam1, kostka, axu, up, salcedo, lara, upc1]

    # load all nodes
    for node in nodes:
        node.load_neighbors_from_file("neighbors.txt")

    # NodeA sends interest to NodeB
    """ nodeB.add_cs("sensor/data", "Temperature: 28C")
    nodeC.add_cs("sensor/data", "Temperature: 28C") """

    # NodeA -> NodeB, NodeB -> NodeC
    """ nodeA.add_fib("sensor/data", 5002, 30)
    nodeB.add_fib("sensor/data", 5003, 30) """

    dpc1.send_interest(seq_num=1, name="sensor/data", flags=ACK_FLAG, target=("127.0.0.1", 5002))

    time.sleep(2)

    # neighbor tables
    print("\n--- Neighbor Tables ---")
    print("NodeA neighbors:", dpc1.get_neighbors())
    print("NodeB neighbors:", andrew.get_neighbors())
    print("NodeC neighbors:", henry.get_neighbors())

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for node in nodes:
            node.stop()
