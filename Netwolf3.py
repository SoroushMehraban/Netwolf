import socket
import threading
import json
from collections import OrderedDict
from time import sleep

DISCOVERY_MSG_LENGTH_SIZE = 1024 * 1024 * 2  # 2MB is maximum length
DISCOVERY_FILE_NAME = "Netwolf3.json"

name, address, port = 0, 0, 0  # will be set in function "get_host_info_by_user"
mutex = threading.Lock()  # for avoiding R/W on discovery file at the same time


def get_host_info_by_user():
    global name, address, port

    print("Enter your name in cluster:")
    name = input("> ")

    print("Select your host:")
    print("1) local host  2) choose manually")
    host_mode = int(input("> "))
    if host_mode == 1:
        address = 'localhost'
    else:
        print("Enter your host address:")
        address = input(">")

    print("Enter port that it listens by (it should be greater than 1023): ")
    port = int(input("> "))
    while port <= 1023:
        print("Wrong input, please enter port greater than 1023: ")
        port = int(input("> "))


def start_discovery_server():
    host_info = (address, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(host_info)
    # print("[SERVER LISTENS] address:{} | port:{}".format(address, port))
    while True:
        msg, addr = server.recvfrom(DISCOVERY_MSG_LENGTH_SIZE)
        #print("[MESSAGE RECEIVED] {}".format(msg))
        threading.Thread(target=handle_received_msg, args=[msg]).start()


def handle_received_msg(msg):
    our_cluster = open_file()

    received_cluster = json.loads(msg.decode("utf-8"), object_pairs_hook=OrderedDict)
    received_cluster.pop(name)  # remove our node from received cluster

    machine_name = is_discovery_between_physical_machines(received_cluster)

    if machine_name is False:
        for node in received_cluster:
            our_cluster[node] = received_cluster[node]
    else:
        sender_server_info = received_cluster.pop(machine_name)
        our_cluster[machine_name] = {
            "address": "{}".format(sender_server_info),
            "cluster": received_cluster
        }

    update_file(our_cluster)


def is_discovery_between_physical_machines(received_cluster):
    if address == "localhost":  # if we are in a local host, then it means that it's not between machines
        return False

    first_element = get_first(received_cluster)
    first_node_name = first_element[0]
    first_address = first_element[1].split(":")[0]
    if first_address != 'localhost':
        return first_node_name
    else:
        return False


def get_first(ordered_dict):
    return next(iter(ordered_dict.items()))


def start_discovery_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        cluster = open_file()
        sending_cluster = cluster.copy()
        add_our_address_to_first(sending_cluster)

        for node in cluster:
            is_not_in_physical_machine = not isinstance(cluster[node], str)
            if is_not_in_physical_machine:
                if address == "localhost":  # localhost let the main node send message to it
                    continue
                else:  # in case if we are main host
                    node_address, node_port = cluster[node]["address"].split(":")
                    client.sendto(bytes(json.dumps(sending_cluster), 'utf-8'), (node_address, int(node_port)))
                    continue

            node_address, node_port = cluster[node].split(":")

            client.sendto(bytes(json.dumps(sending_cluster), 'utf-8'), (node_address, int(node_port)))

        sleep(2)


def add_our_address_to_first(sending_cluster):
    sending_cluster.update({name: "{}:{}".format(address, port)})
    sending_cluster.move_to_end(name, last=False)


def open_file():
    try:
        mutex.acquire()

        read_file = open(DISCOVERY_FILE_NAME, "r")
        data = json.load(read_file, object_pairs_hook=OrderedDict)
        read_file.close()

        mutex.release()
        return data
    except FileNotFoundError:
        mutex.acquire()

        write_file = open(DISCOVERY_FILE_NAME, "w")
        json.dump({}, write_file)
        write_file.close()

        read_file = open(DISCOVERY_FILE_NAME, "r")
        data = json.load(read_file, object_pairs_hook=OrderedDict)
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
