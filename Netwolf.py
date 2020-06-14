import socket
import threading
import json
from time import sleep

DISCOVERY_MSG_LENGTH_SIZE = 1024 * 1024 * 2  # 2MB is maximum length
DISCOVERY_FILE_NAME = "Netwolf1.json"

name, address, port = 0, 0, 0  # will be set in function "get_host_info_by_user"
mutex = threading.Lock()  # for avoiding R/W on discovery file at the same time


def get_host_info_by_user():
    global name, address, port

    print("Enter your name in cluster:")
    name = input("> ")

    print("Select your host:")
    print("1) Main host   2) Local host")
    host_mode = int(input("> "))
    if host_mode == 1:
        address = socket.gethostbyname(socket.gethostname())
    else:
        address = "127.0.0.1"

    print("Enter port that it listens by (it should be greater than 1023): ")
    port = int(input("> "))
    while port <= 1023:
        print("Wrong input, please enter port greater than 1023: ")
        port = int(input("> "))


def start_discovery_server():
    host_info = (address, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(host_info)
    while True:
        msg, sender_address = server.recvfrom(DISCOVERY_MSG_LENGTH_SIZE)
        # print("[MESSAGE RECEIVED] {}".format(msg))
        threading.Thread(target=handle_received_msg, args=(msg, sender_address)).start()


def handle_received_msg(msg, sender_address):
    our_cluster = open_file()

    received_cluster = json.loads(msg.decode("utf-8"))
    received_cluster.pop(name)  # remove our node from received cluster

    if address == "127.0.0.1" or sender_address.split(":")[0] == "127.0.0.1":
        # if connection is inside a physical machine
        for node in received_cluster:
            if not our_cluster.__contains__(node):
                our_cluster[node] = received_cluster[node]
    else:
        pass
        # TODO

    update_file(our_cluster)


def start_discovery_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        cluster = open_file()
        sending_cluster = cluster.copy()
        sending_cluster[name] = "{}:{}".format(address, port)

        for node in cluster:
            node_address, node_port = cluster[node].split(":")
            client.sendto(bytes(json.dumps(sending_cluster), 'utf-8'), (node_address, int(node_port)))
        sleep(30)


def open_file():
    try:
        mutex.acquire()

        read_file = open(DISCOVERY_FILE_NAME, "r")
        data = json.load(read_file)
        read_file.close()

        mutex.release()
        return data
    except FileNotFoundError:
        mutex.acquire()

        write_file = open(DISCOVERY_FILE_NAME, "w")
        json.dump({}, write_file)
        write_file.close()

        read_file = open(DISCOVERY_FILE_NAME, "r")
        data = json.load(read_file)
        read_file.close()

        mutex.release()
        return data


def update_file(cluster):
    mutex.acquire()

    write_file = open(DISCOVERY_FILE_NAME, "w")
    json.dump(cluster, write_file)
    write_file.close()

    mutex.release()


if __name__ == "__main__":
    get_host_info_by_user()

    threading.Thread(target=start_discovery_server).start()
    threading.Thread(target=start_discovery_client()).start()
