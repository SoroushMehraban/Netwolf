import socket
import threading
import json
from collections import OrderedDict
from time import sleep
import subprocess
import os

DISCOVERY_MSG_LENGTH_SIZE = 1024 * 1024 * 2  # 2MB is maximum length
DISCOVERY_FILE_NAME = "Netwolf3.json"
OUR_FILE_DIRECTORY = 'N3'
discovery_message_delay = 0

name, address, port = 0, 0, 0  # will be set in function "get_host_info_by_user"
mutex = threading.Lock()  # for avoiding R/W on discovery file at the same time


def find_Wifi_IPv4():
    local_IPv4 = ""

    try:
        output = subprocess.run(['ipconfig', '/all'], stdout=subprocess.PIPE)
        output_str = output.stdout.decode("utf-8")
        try:
            starting_point = output_str.split("Wireless LAN adapter Wi-Fi")[1].split("IPv4 Address")[1].split(": ")[1]
        except IndexError:
            return None
        for char in starting_point:
            if char.isdigit() or char == '.':
                local_IPv4 += char
            else:
                break
    except FileNotFoundError:
        try:
            output = subprocess.run(['ifconfig'], stdout=subprocess.PIPE)
            output_str = output.stdout.decode("utf-8")
            starting_point = ""
            try:
                starting_point = output_str.split("wlo")[1].split("inet ")[1]
            except IndexError:
                return None
            for char in starting_point:
                if char.isdigit() or char == '.':
                    local_IPv4 += char
                else:
                    break
        except FileNotFoundError:
            print(
                "In order to find your Wifi IPv4 automatically, Please install ifconfig in your OS then run this program again(command: sudo apt install net-tools)")
            return None

    return local_IPv4


def get_host_info_by_user():
    global name, address, port, discovery_message_delay
    IPv4 = find_Wifi_IPv4()

    print("Enter your name in cluster:")
    name = input("> ")

    print("Select your host address:")
    if IPv4 is None:
        print("1) local host  2) choose manually")

        while True:
            host_mode = int(input("> "))
            if host_mode == 1:
                address = 'localhost'
                break
            elif host_mode == 2:
                print("Enter your host address:")
                address = input(">")
                break
    else:
        print("1) local host  2) your WiFi IPv4({}) 3) choose manually".format(IPv4))
        while True:
            host_mode = int(input("> "))
            if host_mode == 1:
                address = 'localhost'
                break
            elif host_mode == 2:
                address = IPv4
                break
            elif host_mode == 3:
                print("Enter your host address:")
                address = input(">")
                break

    print("Enter port that it listens by (it should be greater than 1023): ")
    port = int(input("> "))
    while port <= 1023:
        print("Wrong input, please enter port greater than 1023: ")
        port = int(input("> "))

    print("Enter time delay (in sec) for sending discovery message:")
    discovery_message_delay = int(input("> "))
    while discovery_message_delay <= 0:
        print("Time delay should be greater than 0:")
        discovery_message_delay = input("> ")


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


def start_UDP_server():
    host_info = (address, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(host_info)
    # print("[SERVER LISTENS] address:{} | port:{}".format(address, port))
    while True:
        msg, addr = server.recvfrom(DISCOVERY_MSG_LENGTH_SIZE)
        msg_str = msg.decode("utf-8")
        if msg_str[0:3] == 'get':
            print("[MESSAGE RECEIVED] {}".format(msg))
            threading.Thread(target=handle_get_msg, args=[msg_str]).start()
        else:
            threading.Thread(target=handle_discovery_msg, args=[msg_str]).start()


def handle_get_msg(msg):
    msg_list = msg.split("get ")
    if len(msg_list) < 2:
        return
    file_name = msg_list[1]
    files_list = os.listdir(OUR_FILE_DIRECTORY)
    if files_list.__contains__(file_name):
        print("I have it!")
    else:
        print("I Don't have it!")


def handle_discovery_msg(msg):
    our_cluster = open_file()

    received_cluster = json.loads(msg, object_pairs_hook=OrderedDict)
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

        sleep(discovery_message_delay)


def start_client_interface():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        client_request = input("> ")

        if client_request.__contains__("get"):
            print("Valid Request")
            client_request_list = client_request.split("get")

            if len(client_request_list) > 1:
                cluster = open_file()

                for node in cluster:
                    node_address, node_port = cluster[node].split(":")
                    client.sendto(bytes(client_request, 'utf-8'), (node_address, int(node_port)))


if __name__ == "__main__":
    get_host_info_by_user()

    threading.Thread(target=start_UDP_server).start()
    threading.Thread(target=start_discovery_client).start()
    threading.Thread(target=start_client_interface).start()
