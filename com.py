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

if __name__ == "__main__":
    nodeA = Node("NodeA", port=5001)
    nodeB = Node("NodeB", port=5002)

    # NodeA sends interest to NodeB
    #nodeB.add_cs("sensor/data", "Temperature: 28C")
    #print(nodeB.cs)
    
    nodeB.add_fib("sensor/data", "eth0", 30)
    print(nodeB.fib)
    nodeA.send_interest(seq_num=1, name="sensor/data", flags=ACK_FLAG, target=("127.0.0.1", 5002))

    # NodeB replies with data
    # nodeB.send_data(seq_num=2, name="sensor/data", payload="Temperature: 28C", flags=ACK_FLAG, target=("127.0.0.1", 5001))

    time.sleep(2)

    # neighbor tables
    print("\n--- Neighbor Tables ---")
    print("NodeA neighbors:", nodeA.get_neighbors())
    print("NodeB neighbors:", nodeB.get_neighbors())

    # Keep running
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        nodeA.stop()
        nodeB.stop()
