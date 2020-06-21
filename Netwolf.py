import socket
import threading
import json
from collections import OrderedDict
from time import sleep, time
import subprocess
import os

DISCOVERY_MSG_LENGTH_SIZE = 1024 * 1024 * 2  # 2MB is maximum length
TCP_INSTRUCTION_LENGTH = 128
DISCOVERY_FILE_NAME = "Netwolf1.json"
OUR_FILE_DIRECTORY = 'N1'
discovery_message_delay = 0
get_message_delay = 0
number_of_concurrent_connections = 0
concurrent_connections_length = 0
contain_list = {}
prior_communications = {}

name, address, port = 0, 0, 0  # will be set in function "get_info_by_user"
TCP_port = 0  # will be set in function "start_TCP_server"
mutex = threading.Lock()  # for avoiding R/W on discovery file at the same time


def update_free_ride_file(node_info):
    node_address = node_info.split("_")[1].split(":")[0]
    node_UDP_port = node_info.split("_")[1].split("-")[0].split(":")[-1]
    node_entry = "{}:{}".format(node_address, node_UDP_port)

    node_is_inside_machine = is_inside_machine(node_entry)
    if node_is_inside_machine:
        prior_communications[node_entry] = current_milli_time()
    else:
        print(node_entry)
        main_entry = find_main_info_of_local_node(node_entry)
        if main_entry is None:
            print("Error in updating free ride prior communication list!")
            exit()
        if prior_communications.__contains__(main_entry):
            prior_communications[main_entry]["nodes"][node_entry] = current_milli_time()
        else:
            prior_communications[main_entry] = {"delay": None, "nodes": {node_entry: current_milli_time()}}


def find_main_info_of_local_node(node_entry):
    our_cluster = open_file(False)
    for node in our_cluster:
        if not isinstance(our_cluster[node], str):
            for local_node in our_cluster[node]["cluster"]:
                if our_cluster[node]["cluster"][local_node] == node_entry:
                    return node
    return None


def is_inside_machine(node_entry):
    our_cluster = open_file(False)
    for node in our_cluster:
        if isinstance(our_cluster[node], str):
            if our_cluster[node] == node_entry:
                return True
        elif our_cluster[node]["address"] == node_entry:
            return True
    return False


def current_milli_time():
    return int(round(time() * 1000))


def free_ride(node_address, node_port, main_address=0, main_port=0):
    node_info = "{}:{}".format(node_address, node_port)
    main_info = "{}:{}".format(main_address, main_port)
    print("Prior communications:")
    print(prior_communications)

    if main_address == 0:
        if prior_communications.__contains__(node_info):
            if isinstance(prior_communications[node_info], int):
                last_time = prior_communications[node_info]
                current_time = current_milli_time()
                delay = (current_time - last_time) / 100000  # delay 0.01 sec for 1 sec difference
                print("Delay : {}".format(delay))
                sleep(delay)
            else:
                last_time = prior_communications[node_info]["delay"]
                current_time = current_milli_time()
                if last_time is None:
                    prior_communications[node_info]["delay"] = current_milli_time()
                    return
                delay = (current_time - last_time) / 100000  # delay 0.01 sec for 1 sec difference
                print("Delay : {}".format(delay))
                sleep(delay)
        else:
            prior_communications[node_info] = current_milli_time()
    else:  # node is in another physical machine
        if prior_communications.__contains__(main_info):
            if prior_communications[main_info]["nodes"].__contains__(node_info):
                last_time = prior_communications[main_info]["nodes"][node_info]
                current_time = current_milli_time()
                prior_communications[main_info]["nodes"][node_info] = current_time

                delay = (current_time - last_time) / 100000  # delay 0.01 sec for 1 sec difference
                print("Delay : {}".format(delay))
                sleep(delay)
            else:
                prior_communications[main_info]["nodes"][node_info] = current_milli_time()
        else:
            prior_communications[main_info] = {"delay": None, "nodes": {node_info: current_milli_time()}}


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


def get_info_by_user():
    global name, address, port, discovery_message_delay, get_message_delay, concurrent_connections_length
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

    print("Enter time delay (in sec) for waiting response of get message:")
    get_message_delay = int(input("> "))
    while get_message_delay <= 0:
        print("Time delay should be greater than 0:")
        get_message_delay = input("> ")

    print("Enter number of connections that you want to handle at the same time:")
    concurrent_connections_length = int(input("> "))
    while concurrent_connections_length <= 0:
        print("Time delay should be greater than 0:")
        concurrent_connections_length = input("> ")


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
    sending_cluster.move_to_end(name, last=False)  # send updated value to first of ordered dict


def open_file(ordered=True):
    try:
        mutex.acquire()

        read_file = open(DISCOVERY_FILE_NAME, "r")
        if ordered:
            data = json.load(read_file, object_pairs_hook=OrderedDict)
        else:
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


def start_TCP_server():
    global TCP_port

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, 0))
    TCP_port = server.getsockname()[1]

    print("[TCP SERVER LISTENS] address:{} | port:{}".format(address, TCP_port))

    server.listen()
    while True:
        connection, socket_address = server.accept()
        threading.Thread(target=handle_TCP_request, args=[connection]).start()


def handle_TCP_request(connection):
    msg = connection.recv(TCP_INSTRUCTION_LENGTH).decode("utf-8")
    print("[TCP MESSAGE RECEIVED] {}".format(msg))
    msg_list = msg.split(" ")
    file_name = msg_list[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if msg_list[0] == "send":
        listening_address, listening_port = msg_list[2].split(":")

        client.connect((listening_address, int(listening_port)))

        f = open("{}\{}".format(OUR_FILE_DIRECTORY, file_name), 'rb')
        contents = f.read()
        f.close()

        send_TCP_msg(client, contents, False)
    elif msg_list[0].split("_")[0] == "redirect-send":
        file_size = int(msg_list[0].split("_")[1])
        if len(msg_list) > 3:
            chain_nodes = msg_list[2].split("-")
            temp_server, temp_port = start_temp_TCP_server()

            if len(chain_nodes) == 1:
                next_hop_address, next_hop_port = chain_nodes[0].split(":")[0: 2]
                client.connect((next_hop_address, int(next_hop_port)))
                send_TCP_msg(client, "redirect-send_{} {} {}:{}".format(file_size, file_name, address, temp_port), True)
            else:
                next_hop_address, next_hop_port = chain_nodes[-1].split(":")[0: 2]
                next_hop_chain_nodes = msg_list[2].split("-" + chain_nodes[-1])[0]

                client.connect((next_hop_address, int(next_hop_port)))
                send_TCP_msg(client,
                             "redirect-send_{} {} {} {}:{}".format(file_size, file_name, next_hop_chain_nodes, address,
                                                                   temp_port),
                             True)

            connection, addr = temp_server.accept()
            msg = connection.recv(file_size)
            temp_server.close()

            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            returning_address, returning_port = msg_list[3].split(":")
            client2.connect((returning_address, int(returning_port)))

            send_TCP_msg(client2, msg, False)
            client2.close()
        else:  # last hop
            f = open("{}\{}".format(OUR_FILE_DIRECTORY, file_name), 'rb')
            contents = f.read()
            f.close()

            returning_address, returning_port = msg_list[2].split(":")
            client.connect((returning_address, int(returning_port)))
            send_TCP_msg(client, contents, False)

    client.close()


def start_UDP_server():
    global number_of_concurrent_connections

    host_info = (address, port)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(host_info)
    print("[UDP SERVER LISTENS] address:{} | port:{}".format(address, port))
    while True:
        msg, addr = server.recvfrom(DISCOVERY_MSG_LENGTH_SIZE)
        msg_str = msg.decode("utf-8")

        if msg_str[0] != '{':  # if it's not discovery message
            if number_of_concurrent_connections < concurrent_connections_length + 1:
                number_of_concurrent_connections += 1
            if number_of_concurrent_connections == concurrent_connections_length + 1:
                continue

        if msg_str[0:3] == 'get':
            print("[GET RECEIVED] {}".format(msg))
            threading.Thread(target=handle_get_msg, args=[msg_str]).start()
        elif msg_str[0:7] == 'contain':
            print("[CONTAIN RECEIVED] {}".format(msg))
            threading.Thread(target=handle_contain_msg, args=[msg_str]).start()
        elif msg_str[0:12] == "GET-REDIRECT":
            print("[GET-REDIRECT RECEIVED] {}".format(msg))
            threading.Thread(target=handle_redirect_get_msg, args=[msg_str]).start()
        elif msg_str[0:16] == "CONTAIN-REDIRECT":
            print("[CONTAIN-REDIRECT RECEIVED] {}".format(msg))
            threading.Thread(target=handle_redirect_contain_msg, args=[msg_str]).start()
        else:
            threading.Thread(target=handle_discovery_msg, args=[msg_str]).start()


def handle_redirect_contain_msg(msg):
    global number_of_concurrent_connections

    msg_list = msg.split(" ")
    info = msg_list[1]
    dest_address, dest_port = msg_list[2].split(":")

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if len(msg_list) == 3:
        client.sendto(bytes("contain {} {}:{}:{}".format(info, address, TCP_port, port), 'utf-8'),
                      (dest_address, int(dest_port)))
    elif len(msg_list) == 4:
        source_address, source_port = msg_list[3].split(":")
        client.sendto(
            bytes(
                "CONTAIN-REDIRECT {}-{}:{}:{} {}:{}".format(info, address, TCP_port, port, source_address, source_port),
                'utf-8'),
            (dest_address, int(dest_port)))

    number_of_concurrent_connections -= 1


def handle_contain_msg(msg):
    global contain_list, number_of_concurrent_connections

    receive_time = current_milli_time()

    msg_list = msg.split(" ")
    node_info = msg_list[1]

    if len(msg_list) == 3:
        node_info += "-{}".format(msg_list[2])

    contain_list[node_info] = receive_time
    number_of_concurrent_connections -= 1


def handle_redirect_get_msg(msg):
    global number_of_concurrent_connections

    msg_list = msg.split(" ")
    if len(msg_list) != 4 and len(msg_list) != 5:
        return
    file_name = msg_list[1]
    node_address, node_port = msg_list[2].split(":")
    source_address, source_port = msg_list[3].split(":")

    connected_between_machines = address != 'localhost' and node_address != "localhost"
    if connected_between_machines:
        threading.Thread(target=handle_inner_redirect_get_node,
                         args=(node_address, node_port, source_address, source_port, file_name)).start()

    files_list = os.listdir(OUR_FILE_DIRECTORY)
    if files_list.__contains__(file_name):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        file_size = os.path.getsize("{}\{}".format(OUR_FILE_DIRECTORY, file_name))
        if len(msg_list) == 4:
            if (not msg_list[2].__contains__("localhost")) and (not msg_list.__contains__("localhost")):
                free_ride(source_address, source_port)
            client.sendto(
                bytes(
                    "CONTAIN-REDIRECT {}_{}:{}:{} {}:{}".format(file_size, address, TCP_port, port, source_address,
                                                                source_port),
                    'utf-8'),
                (node_address, int(node_port)))
        else:
            origin_address, origin_port = msg_list[4].split(":")

            free_ride(origin_address, origin_port, source_address, source_port)
            client.sendto(
                bytes("CONTAIN-REDIRECT {}_{}:{}:{} {}:{} {}:{}".format(file_size, address, TCP_port, port,
                                                                        source_address,
                                                                        source_port,
                                                                        origin_address, origin_port), 'utf-8'),
                (node_address, int(node_port)))

    number_of_concurrent_connections -= 1


def handle_inner_redirect_get_node(source_address, source_port, origin_address, origin_port, file_name):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    our_cluster = open_file()
    for node in our_cluster:
        node_is_inside_machine = isinstance(our_cluster[node], str)
        if node_is_inside_machine:
            dest_address, dest_port = our_cluster[node].split(":")
            client.sendto(
                bytes("GET-REDIRECT {} {}:{} {}:{} {}:{}".format(file_name, address, port, source_address, source_port,
                                                                 origin_address, origin_port),
                      'utf-8'),
                (dest_address, int(dest_port)))


def handle_get_msg(msg):
    global number_of_concurrent_connections
    msg_list = msg.split(" ")
    if len(msg_list) != 3:
        return
    file_name = msg_list[1]
    node_address, node_port = msg_list[2].split(":")

    connected_between_machines = address != 'localhost' and node_address != "localhost"
    if connected_between_machines:
        threading.Thread(target=handle_inner_get_node, args=(node_address, node_port, file_name)).start()

    local_to_main_node = address != "localhost" and node_address == "localhost"
    if local_to_main_node:
        threading.Thread(target=handle_local_to_main_node, args=(node_address, node_port, file_name)).start()

    files_list = os.listdir(OUR_FILE_DIRECTORY)
    if files_list.__contains__(file_name):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        file_size = os.path.getsize("{}\{}".format(OUR_FILE_DIRECTORY, file_name))

        free_ride(node_address, node_port)
        client.sendto(bytes("contain {}_{}:{}:{}".format(file_size, address, TCP_port, port), 'utf-8'),
                      (node_address, int(node_port)))

    number_of_concurrent_connections -= 1


def handle_local_to_main_node(source_address, source_port, file_name):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    our_cluster = open_file()
    for node in our_cluster:
        node_is_outside_machine = not isinstance(our_cluster[node], str)
        if node_is_outside_machine:
            node_address, node_port = our_cluster[node]["address"].split(":")
            client.sendto(
                bytes("GET-REDIRECT {} {}:{} {}:{}".format(file_name, address, port, source_address, source_port),
                      'utf-8'),
                (node_address, int(node_port)))


def handle_inner_get_node(source_address, source_port, file_name):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    our_cluster = open_file()
    for node in our_cluster:
        node_is_inside_machine = isinstance(our_cluster[node], str)
        if node_is_inside_machine:
            node_address, node_port = our_cluster[node].split(":")
            client.sendto(
                bytes("GET-REDIRECT {} {}:{} {}:{}".format(file_name, address, port, source_address, source_port),
                      'utf-8'),
                (node_address, int(node_port)))


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


def find_nearest_node():
    return min(contain_list.keys(), key=(lambda k: contain_list[k]))


def inform_user_about_containers():
    number_of_containers = len(contain_list)
    if number_of_containers == 0:
        print("* No one has your file")
        return False
    elif number_of_containers == 1:
        print("* Only one node has your file")
        print("* Request to get the file...")
    else:
        print("* Found your file in {} nodes".format(len(contain_list)))
        print("* Request to get from the nearest node...")
    return True


def send_get_request(client_request):
    global contain_list

    cluster = open_file()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    contain_list = {}
    for node in cluster:
        node_is_inner_node = isinstance(cluster[node], str)
        if node_is_inner_node:
            node_address, node_port = cluster[node].split(":")
            client.sendto(bytes("{} {}:{}".format(client_request, address, port), 'utf-8'),
                          (node_address, int(node_port)))
        elif address != 'localhost':
            node_address, node_port = cluster[node]["address"].split(":")
            if node_address != address:
                client.sendto(bytes("{} {}:{}".format(client_request, address, port), 'utf-8'),
                              (node_address, int(node_port)))


def send_TCP_msg(source_socket, msg, is_str):
    if is_str:
        message = msg.encode("utf-8")
        source_socket.send(message)
    else:
        source_socket.send(msg)


def write_binary_file(file_name, content):
    file_destination = "{}\{}".format(OUR_FILE_DIRECTORY, file_name)
    f = open(file_destination, 'w+b')
    f.write(content)
    f.close()


def start_temp_TCP_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((address, 0))
    temp_TCP_port = server.getsockname()[1]
    server.listen()
    return server, temp_TCP_port


def request_to_get_file(info, file_name):
    info_list = info.split("_")
    print("info list: {}".format(info_list))
    file_size = int(info_list[0])

    connection_is_direct = not info_list[1].__contains__("-")
    if connection_is_direct:
        server, temp_TCP_port = start_temp_TCP_server()

        dest_address, dest_port = info_list[1].split(":")[0: 2]
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((dest_address, int(dest_port)))
        send_TCP_msg(client, "send {} {}:{}".format(file_name, address, temp_TCP_port), True)

        connection, addr = server.accept()
        msg = connection.recv(file_size)
        print("file received")
        write_binary_file(file_name, msg)
        print("file saved on your node directory")
        server.close()
    else:
        server, temp_TCP_port = start_temp_TCP_server()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        chain_nodes = info_list[1].split("-")
        next_hop_address, next_hop_port = chain_nodes[-1].split(":")[0: 2]
        next_hope_chain_nodes = info_list[1].split("-" + chain_nodes[-1])[0]
        client.connect((next_hop_address, int(next_hop_port)))
        send_TCP_msg(client,
                     "redirect-send_{} {} {} {}:{}".format(file_size, file_name, next_hope_chain_nodes, address,
                                                           temp_TCP_port), True)

        connection, addr = server.accept()
        msg = connection.recv(file_size)
        print("file received")
        write_binary_file(file_name, msg)
        print("file saved on your node directory")
        server.close()


def add_new_node():
    print("Enter your node name:")
    input_name = input("> ")

    print("Enter your node type:")
    print("1) local     2) other")
    command = input("> ")
    while command != '1' and command != '2':
        print("Invalid command, try again")
        command = input("> ")

    if command == '2':
        print("Enter your node address:")
        input_address = input("> ")
        while len(input_address.split(".")) != 4:
            print("Wrong input, your input should be in dotted decimal format of IPv4(x.x.x.x)")
            input_address = input("> ")

    print("Enter port number:")
    input_port = input("> ")
    while not input_port.isdigit():
        print("your port should be a number")
        input_port = input("> ")

    our_cluster = open_file()

    if command == '1':
        our_cluster[input_name] = "localhost:{}".format(input_port)
    else:
        our_cluster[input_name] = {
            "address": "{}:{}".format(input_address, input_port),
            "cluster": {}
        }

    update_file(our_cluster)


def start_client_interface():
    print("---------------------------------------------------------------------------------")
    print("Commands guidance:")
    print("get <file_name> : search your file name through nodes and download if it exists")
    print("list : list all of existing nodes")
    print("add : add a new node to your node file ({})".format(DISCOVERY_FILE_NAME))
    print("---------------------------------------------------------------------------------")

    while True:
        client_request = input("> ")

        if client_request.__contains__("get"):
            client_request_list = client_request.split("get ")
            if len(client_request_list) > 1:
                print("Searching...")
                send_get_request(client_request)
                sleep(get_message_delay)
                someone_has_our_file = inform_user_about_containers()
                if someone_has_our_file:
                    nearest_node_info = find_nearest_node()
                    file_name = client_request_list[1]
                    update_free_ride_file(nearest_node_info)
                    request_to_get_file(nearest_node_info, file_name)
        if client_request == "list":
            our_cluster = open_file(False)
            for node in our_cluster:
                print("{} {}".format(node, our_cluster[node]))
        if client_request == "add":
            add_new_node()
            print("Node added successfully")


if __name__ == "__main__":
    get_info_by_user()

    threading.Thread(target=start_UDP_server).start()
    threading.Thread(target=start_TCP_server).start()
    threading.Thread(target=start_discovery_client).start()
    sleep(0.5)
    threading.Thread(target=start_client_interface).start()
