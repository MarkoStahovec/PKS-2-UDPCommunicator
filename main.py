import os
import sys
import select
import random
import struct
import threading
import socket
import time
import concurrent.futures

import checksum_algorithm

# all types of flags accesible with indexing
types = ["INIT", "FINIT", "MINIT", "DATT", "DATTC", "DATTE", "DPING", "CTERM", "SWAP"]
keep_connected_daemon_status = False  # global flag that sets status of a thread that maintains connection
msg_from_server = None  # message from server to client when server tries to swap roles or quit
server_input = None  # this variable holds server input, since it is managed by multiple threading objects
ETH_MTU = 1500  # maximum ethernet tu without its header
MTU = 1465  # maximum transmission unit without all headers including this
MAX_NO_FRAGMENTS = 65535
HEADER_SIZE = 7
IDLE_MESSAGE_THRESHOLD = 3  # how many times does server need to timeout when waiting for data messages
DPING_INIT_CONSTANT = 5  # dping timeout
SNAP_WAIT = 0.5
SHORT_WAIT = 10
MEDIUM_WAIT = 20
LONG_WAIT = 40


# this class represents both client and a server
class Host:
    def __init__(self, socket_, other_host):
        self.socket_ = socket_
        self.other_host_addr_ = other_host


# 0 - INITIALIZE CONNECTION (INIT)
# 1 - INITIALIZE FILE TRANSFER (FINIT)
# 2 - INITIALIZE MESSAGE TRANSFER (MINIT)
# 3 - DATA TRANSFER (DATT)
# 4 - DATA TRANSFERED CORRECTLY (DATTC)
# 5 - DATA TRANSFERED WITH ERROR (DATTE)
# 6 - DAEMON PING (DPING)
# 7 - CLIENT CONNECTION TERMINATION (CTERM)
# 8 - SWAP ROLES BETWEEN HOSTS (SWAP)


# prints out information after data transfer is over
def print_transfer_stats(correct, error):
    print("\n*************************************")
    print(f"[INFO] -- CORRECTLY DELIVERED FRAGMENTS: {correct}")
    print(f"[INFO] -- PACKETS WITH ERROR: {error}")
    print("*************************************\n")
    return


# UNIX only solution to timed-input control
def server_input_check():
    print("# -- Choice: ")  # prompt choice
    i, o, e = select.select([sys.stdin], [], [], DPING_INIT_CONSTANT / 1.05)  # use select to capture input from stdin

    if i:
        return str(i)  # if input was given in time, return it
    else:
        print("\n[INFO] -- Server is automatically listening...")
        return "1"  # if not, the generic choice is kept


# function to get input and cancel the timer thread, indicating input was given in time
def process_server_input(timer):
    global server_input
    s = input("# -- Choice: ")
    timer.cancel()
    server_input = s


# portable version for user input using two thread types
def server_input_prompt():
    global server_input
    delay = DPING_INIT_CONSTANT / 1.05
    finished = threading.Event()  # Event to start the timer

    timer = threading.Timer(delay, finished.set)
    timer.start()
    worker = threading.Thread(target=process_server_input, args=(timer,))  # worker thread to prompt input with timer
    worker.setDaemon(True)
    worker.start()
    timer.join()

    if server_input is None:  # if nothing was inputted in time, manual input is given for function
        print("\n[INFO] -- Server is automatically listening...")
        server_input = "1"


# this function is used by client to ping server and maintain connection
def keep_connected_daemon_function(client):
    global keep_connected_daemon_status
    restart_flag = True  # flag that ensures, that client resends DPING after unsuccesful try
    while True:  # keep pinging until target flag is not True
        if not keep_connected_daemon_status:
            return
        else:
            # send DPING to server
            client.socket_.sendto(create_header_and_payload(types.index("DPING")), client.other_host_addr_)

            try:
                client.socket_.settimeout(DPING_INIT_CONSTANT)  # wait a small amount of time for DPING from server
                data, address = client.socket_.recvfrom(ETH_MTU)
                packet_type, pnum, pcheck, pval = unpack_message(data)
                if packet_type == types.index("DPING"):  # if DPING from server was received
                    # print(f"[{types[packet_type]}] -- successful, connection is maintained.")
                    restart_flag = True  # reset restart flag after successful delivery
                else:
                    print(f"\n[{types[types.index('DPING')]}] -- not received from server.")
                    if restart_flag:  # if restart flag is available, turn it off and try again
                        restart_flag = False
                    else:
                        keep_connected_daemon_status = False
                        return

            except socket.error:
                if restart_flag:  # if restart flag is available, turn it off and try again
                    print("\n[DPING] [ERROR] -- Server is not listening. Waiting for response...")
                    restart_flag = False
                else:
                    print("\n[DPING] [ERROR] -- Server is not listening. Thread turning off...")
                    keep_connected_daemon_status = False
                    return

            time.sleep(DPING_INIT_CONSTANT * 1.2)  # delay between pings


# threading function, that continually checks for messages from server and switches event accordingly
def client_message_listener(client, server_status):
    global msg_from_server
    while True:
        if not server_status.is_set():  # when event is sent, stop checking for packets
            return
        else:
            try:
                client.socket_.settimeout(SNAP_WAIT)
                data, address = client.socket_.recvfrom(ETH_MTU)
                packet_type, pnum, pcheck, pval = unpack_message(data)
                # if DPING is received, send it to keep_connected thread, which handles this type of information
                if packet_type == types.index("DPING"):
                    """client.socket_.sendto(create_header_and_payload(types.index("DPING")),
                                          ((socket.gethostbyname(socket.gethostname() + ".local"),
                                            client.socket_.getsockname()[1])))"""
                    client.socket_.sendto(create_header_and_payload(types.index("DPING")), client.socket_.getsockname())
                if packet_type == types.index("SWAP") and not msg_from_server:  # if SWAP is requested
                    msg_from_server = packet_type
                    client.socket_.sendto(create_header_and_payload(types.index("SWAP")), client.other_host_addr_)
                elif packet_type == types.index("CTERM") and not msg_from_server:  # if CTERM was sent
                    msg_from_server = packet_type

            except socket.error:
                pass
                # print("[SWAP] -- Server did not swap.")
            time.sleep(SNAP_WAIT)


# Executor type of function, which operates as a thread, that takes input from user
def client_input():
    option = str(input("# -- Choice: "))
    return option


# concatenates header and data into one packet of specific types
def create_header_and_payload(packet_type, packet_number=0, checksm=0, data=""):
    if type(data) == str:  # in case string format of data was sent
        data = data.encode()

    return struct.pack("B", packet_type) + struct.pack("H", packet_number) + \
        struct.pack("I", checksm) + struct.pack(f"{len(data)}s", data)


# unwrapps all individual header fields and data from a packet
def unpack_message(packet):
    ptype = int((struct.unpack("B", packet[0:1]))[0])
    pnum = int((struct.unpack("H", packet[1:3]))[0])
    pchecksum = int((struct.unpack("I", packet[3:7]))[0])
    pmessage = packet[7:]

    return ptype, pnum, pchecksum, pmessage


# method that initiates connection from a client's side
def client_start():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect to google's dns and extract self private IP, just for printing purposes

    ipaddr = input(f"[IP] -- Input IP address of a server (Your IP: {s.getsockname()[0]}): ")
    s.shutdown(socket.SHUT_RDWR)  # terminate socket
    s.close()  # deallocate all memory belonging to the socket
    while True:  # port input check
        port = input("[PORT] -- Input port number of a server: ")
        if (not port.isnumeric()) or (int(port) < 1024) or (int(port) > 65535):
            continue
        break

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # init client's udp diagram
    server_address = (ipaddr, int(port))  # "bind" input ip and port and try to connect to it

    while True:
        try:
            print("[INFO] -- Sending INIT, waiting for server...")
            client_socket.sendto(create_header_and_payload(types.index("INIT")), server_address)  # send INIT message
            client_socket.settimeout(SHORT_WAIT)
            data, address = client_socket.recvfrom(ETH_MTU)
            packet_type, pnum, pchecksum, pval = unpack_message(data)
            if packet_type == types.index("INIT"):  # if INIT is sent back from server
                print(f"[{types[packet_type]}] -- received, connected to address: {server_address}\n")
                client = Host(client_socket, address)  # create Host instance of client
                client_menu(client)

        except (Exception,):
            print("[ERROR] -- Couldn't establish connection.\n")
            return


# this function tries to establish connection from server's side
def server_start():
    while True:  # port input check
        port = input("[PORT] -- Input port to listen to: ")
        if (not port.isnumeric()) or (int(port) < 1024) or (int(port) > 65535):
            continue
        break

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("", int(port)))  # to bind communication end point
    print("[INFO] -- Waiting for a client...")

    data, address = server_socket.recvfrom(ETH_MTU)
    packet_type, pnum, pchecksum, pval = unpack_message(data)
    if packet_type == types.index("INIT"):  # when INIT is received
        # send INIT back to client as an acknowledgment
        server_socket.sendto(create_header_and_payload(types.index("INIT")), address)
        print(f"[{types[packet_type]}] -- received, established connection from: {address}\n")

        server = Host(server_socket, address)
        server_menu(server)
        server_start()  # restart server after being timed out in order to keep persistance
    else:
        print("[ERROR] -- Couldn't establish connection.")

    return


# this function handles receiving data, printing out all transfer information and creates a file or displays message
def receive_data(server, messagetype, total_fragments, dest_directory):
    not_received_counter = IDLE_MESSAGE_THRESHOLD
    correct_fragments = 0
    error_fragments = 0
    all_data = ""
    pnum = 0
    correct = False
    if messagetype == "f":  # if file is being transfered, data will be stored in bytearray as opposed to string
        all_data = bytearray(b'')
    filename = ""
    print("\n*************************************")
    print(f"[INFO] -- EXPECTED FRAGMENTS: {total_fragments}")
    if messagetype == "f":
        print("[INFO] -- RECEIVING FILE...")
    elif messagetype == "m":
        print("[INFO] -- RECEIVING MESSAGE...")
    print("*************************************\n")
    print("\n-------------------------------------")

    while True:  # here is the cycle that accepts all incoming fragments
        try:
            if correct_fragments == int(total_fragments):  # if all fragments were accepted correctly
                break
            if pnum >= int(total_fragments) - 1 and correct:
                break

            server.socket_.settimeout(SHORT_WAIT)
            data, address = server.socket_.recvfrom(ETH_MTU)
            packet_type, pnum, pchecksum, pval = unpack_message(data)

            # special condition when FINIT/MINIT packets are still buffered
            if packet_type != types.index("DATT") and pnum == 0:
                continue

            checksum = checksum_algorithm.mycrc32(pval)

            if checksum == pchecksum and packet_type == types.index("DATT"):  # if checksum and packet type are correct
                print(f"Packet {pnum} | {len(data)}B | [{types[packet_type]}] | was accepted correctly.")
                # send back DATTC to signal correct transfer
                server.socket_.sendto(create_header_and_payload(types.index("DATTC")), address)
                not_received_counter = IDLE_MESSAGE_THRESHOLD
                correct_fragments += 1
                correct = True
                if messagetype == "m":
                    all_data = all_data + pval.decode()
                else:
                    all_data += pval
            else:
                print(f"Packet {pnum} | {len(data)}B | [{types[packet_type]}] | was REJECTED.")
                print(f"   ↓")
                error_fragments += 1
                # send back DATTE to signal errorpacket
                server.socket_.sendto(create_header_and_payload(types.index("DATTE")), address)
                correct = False
        except socket.timeout:
            print(f"[ERROR] -- Did not receive any packets after {SHORT_WAIT} seconds.")
            not_received_counter -= 1
            if not_received_counter == 0:
                print(f"[ERROR] -- Client is idle, returning back to menu.")
                return

    if messagetype == "f":  # if the transfer regards file, one extra packet including filename is received
        while True:
            data, address = server.socket_.recvfrom(ETH_MTU)
            packet_type, pnum, pchecksum, pval = unpack_message(data)

            checksum = checksum_algorithm.mycrc32(pval)

            if checksum == pchecksum and packet_type == types.index("DATT"):
                server.socket_.sendto(create_header_and_payload(types.index("DATTC")), address)  # DATTC to client
                filename = pval.decode()
                break
            else:
                server.socket_.sendto(create_header_and_payload(types.index("DATTE")), address)  # DATTE to client

    print("-------------------------------------\n")
    print_transfer_stats(correct_fragments, error_fragments)

    if messagetype == "m":  # when message was sent, the content is displayed
        print("-------------------------------------")
        print(f"[OUT] -- MESSAGE: {all_data}")
        print("-------------------------------------\n")
    elif messagetype == "f":
        filename = filename[filename.rfind("/"):len(filename)]  # strip the filename up until last /
        final_path = dest_directory + filename  # concatenate final absolute path for server
        if dest_directory:
            with open(final_path, "wb") as file:  # open file and write bytes into it
                file.write(all_data)

        print("\n-------------------------------------")
        print(f"[INFO] -- File {filename} created successfully.\nFull path: {final_path}\nFile size: "
              f"{os.path.getsize(final_path)}B.")
        print("-------------------------------------\n")


# this function works as a placeholder for all the settings that can be sent by client before transferring data
def set_transfer_settings(messagetype, message, no_of_fragments, err_indices):
    filen = ""
    while True:
        fragment_size = input("[INT] -- Input fragment size: ")  # 1500 - 20 - 8 - 7 = 1465
        if not fragment_size.isnumeric():
            continue
        fragment_size = int(fragment_size)
        # so fragments are not fragged on data link layer and not smaller than HEADER_SIZE
        if fragment_size > MTU or fragment_size <= HEADER_SIZE:
            continue
        break

    fragment_size -= HEADER_SIZE  # decrement HEADER_SIZE, so the size corresponds to user input after adding header

    while True:
        if messagetype == "f":  # input filename and check whether it exists and display its stats
            filen = str(input('[STR] -- Input path to file and its name (ex. \'./map4.txt\'): '))
            if os.path.isfile(filen):
                with open(filen, "rb") as file:
                    message = file.read()
                    print("\n-------------------------------------")
                    print(f"[INFO] -- File {filen} found. Size {os.path.getsize(filen)}B."
                          f"\nAbsolute path: {os.path.abspath(filen)}")
                    print("-------------------------------------\n")
                break
            else:
                continue
        elif messagetype == "m":
            message = str(input("[STR] -- Input message: ")).encode()
            break

    if messagetype == "f":  # calculate amount of fragments that will be sent during transfer
        if os.path.getsize(filen) % fragment_size == 0:
            no_of_fragments = int(os.path.getsize(filen) / fragment_size)
        else:
            no_of_fragments = int((os.path.getsize(filen) / fragment_size)) + 1
    elif messagetype == "m":
        if len(message) % fragment_size == 0:
            no_of_fragments = int(len(message) / fragment_size)
        else:
            no_of_fragments = int((len(message) / fragment_size)) + 1

    if no_of_fragments > MAX_NO_FRAGMENTS:
        print("[ERROR] -- Cannot send that many fragments. Try again.\n")
        return 0, "", "", 0, 0, []

    while True:
        error_packets = input("[INT] -- Set amount of error packets: ")
        if not error_packets.isnumeric():
            continue
        error_packets = int(error_packets)
        if error_packets > no_of_fragments or error_packets < 0:
            continue
        break

    while error_packets != len(err_indices):  # generate random packet numbers that will contain error within
        randval = random.randint(1, no_of_fragments)
        if randval not in err_indices:
            err_indices.append(randval)

    return fragment_size, filen, message, no_of_fragments, error_packets, err_indices


# this function creates an error in data field of a packet, when its index was chosen to contain error
def make_error_packet(error_packets, packet_num, error_packets_indices, next_fragment):
    if error_packets > 0:
        if packet_num in error_packets_indices:
            next_fragment = bytearray(next_fragment)  # convert fragment to bytearray so its content is alterable
            randbyte = random.randint(0, len(next_fragment) - 1)  # choose random byte that will be altered
            if int(next_fragment[randbyte]) != 255:  # alter byte value accordingly
                next_fragment[randbyte] = int(next_fragment[randbyte]) + 1
            else:
                next_fragment[randbyte] = int(next_fragment[randbyte]) - 1

            error_packets -= 1
            error_packets_indices.remove(packet_num)
            next_fragment = bytes(next_fragment)  # convert fragment back to bytes so it can be transferred

    return next_fragment


# this function handles sending data from client's side, as well as initialization of transfer and printing out progress
def send_data(client, messagetype, fragment_size, filen, message, no_of_fragments,
              error_packets, error_packets_indices):
    error_fragments = correct_fragments = ptype = 0
    packet_num = 1
    restart_flag = True

    while True:  # cycle that initializes specific type of connection to ensure correct data transfer
        if messagetype == "f":  # set packet type accordingly so server knows, what type of data is coming in
            ptype = 1
        elif messagetype == "m":
            ptype = 2

        client.socket_.sendto(create_header_and_payload(ptype, 0, 0, str(no_of_fragments)), client.other_host_addr_)
        print(f"[{types[ptype]}] -- Waiting for acknowledgment")

        try:
            client.socket_.settimeout(MEDIUM_WAIT)  # wait for some time for acknowledgment from server
            data, address = client.socket_.recvfrom(ETH_MTU)
            packet_type, pnum, pchecksum, pval = unpack_message(data)
            if packet_type == types.index("FINIT") and messagetype == "f":
                print(f"[{types[packet_type]}] -- received from: {address}\n")
                break
            elif packet_type == types.index("MINIT") and messagetype == "m":
                print(f"[{types[packet_type]}] -- received from: {address}\n")
                break
            elif packet_type == types.index("CTERM"):
                print("[INFO] -- Server closed the connection.\n")
                exit(1)
            elif packet_type == types.index("SWAP"):
                client.socket_.sendto(create_header_and_payload(types.index("INIT")), client.other_host_addr_)
                # client.socket_.flush()
                print("[ERROR] -- Server requested role swap, but it was declined. Returning to menu.\n")
                return
                # server_menu(client)

        except socket.timeout:
            print("[ERROR] -- Server not responding.\n")
            return

    # HEADER:  TYPE 1B | PACKET NUMBER 2B | CHECKSUM 4B | DATA/PAYLOAD nB
    print("\n-------------------------------------")

    while True:  # data sending cycle
        if len(message) == 0:  # if all contents was consumed
            break
        if correct_fragments % 2 == 0:
            next_fragment = message[:fragment_size]  # split new fragment to be sent
        else:
            correct_fragments += 1
            packet_num += 1
            restart_flag = True
            message = message[fragment_size:]
            continue

        checksum = checksum_algorithm.mycrc32(next_fragment)
        next_fragment = make_error_packet(error_packets,
                                          packet_num, error_packets_indices, next_fragment)

        client.socket_.sendto(create_header_and_payload(types.index("DATT"), packet_num,
                                                        checksum, next_fragment), client.other_host_addr_)

        try:  # try to wait for an acknowledgment from other side
            client.socket_.settimeout(SHORT_WAIT / 2)
            data, address = client.socket_.recvfrom(ETH_MTU)
            packet_type, pnum, pchecksum, pval = unpack_message(data)
            if packet_type == types.index("DATTC"):  # server got the packet correctly, DATTC is received
                print(f"Packet {packet_num} | {len(next_fragment) + 7}B | [{types[packet_type]}] "
                      f"received.")
                correct_fragments += 1
                packet_num += 1
                restart_flag = True
                message = message[fragment_size:]  # move message pointer by fragment_size, moving onto next fragment
            else:  # server got the packet incorrectly, DATTE is received and handled
                print(f"Packet {packet_num} | {len(next_fragment) + 7}B | [{types[packet_type]}] "
                      f"received, retransmitting error fragment...")
                print(f"   ↓")
                error_fragments += 1
                continue

        except socket.timeout:
            if restart_flag:
                print(f"[ERROR] -- Didn't receive DATTC or DATTE packet, retransmitting...")
                error_fragments += 1
                restart_flag = False
                continue

            print(f"[ERROR] -- Couldn't deliver packet {packet_num}, terminating.")
            return

    if messagetype == "f":  # if there was file transfer, send more packet with filename in data field
        while True:
            checksum = checksum_algorithm.mycrc32(filen.encode())
            client.socket_.sendto(create_header_and_payload(types.index("DATT"), packet_num + 1, checksum, filen),
                                  client.other_host_addr_)

            try:
                client.socket_.settimeout(SHORT_WAIT)
                data, address = client.socket_.recvfrom(ETH_MTU)
                packet_type, pnum, pchecksum, pval = unpack_message(data)
                if packet_type == types.index("DATTC"):  # filename was received by the server
                    break
                else:
                    continue

            except socket.timeout:
                print("[ERROR] -- Couldn't deliver filename!")

    print("-------------------------------------\n")
    print_transfer_stats(int(correct_fragments/2), error_fragments)


# this function works as a menu for client, giving client various options to control the program
def client_menu(client):
    global keep_connected_daemon_status
    global msg_from_server
    thread = None  # keep_connected thread
    msg_from_server = None  # specific message from server to client
    keep_checking_server_status = threading.Event()  # event to set checking server status

    while True:
        print("\n-------------- CLIENT --------------\n")
        print("# -- Choose 1 -> Transfer a file\n# -- Choose 2 -> Transfer a message")
        print(f"# -- Choose 3 -> Toggle keep connected status [current status: {keep_connected_daemon_status}]")
        print("# -- Choose 4 -> Swap host roles\n# -- Choose q -> Quit\n")

        restore_daemon_status = False  # flag variable that restores daemon thread status after data transfer
        keep_checking_server_status.set()

        # separate thread to do the checking for server messages
        swap_t = threading.Thread(target=client_message_listener, args=(client, keep_checking_server_status))
        swap_t.daemon = True
        swap_t.start()

        # special thread to get the user input outside of main thread
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(client_input)
            option = future.result()

        keep_checking_server_status.clear()
        # swap_t.join()

        # condition for cases when server requests swap or terminates itself
        if msg_from_server == types.index("SWAP"):
            print("[INFO] -- Server requested role swap.\n")
            if thread:  # stop the thread
                keep_connected_daemon_status = False
                thread.join()
            msg_from_server = None
            server_menu(client)
            return
        elif msg_from_server == types.index("CTERM"):
            print("[INFO] -- Server closed the connection.\n")
            if thread:  # stop the thread
                keep_connected_daemon_status = False
                thread.join()
            msg_from_server = None
            exit(1)

        if option == "1":  # file transfer
            no_of_fragments = 0
            message = ""
            error_packets_indices = []
            # get all settings from client's input
            fragment_size, filen, message, no_of_fragments, error_packets, error_packets_indices = \
                set_transfer_settings("f", message, no_of_fragments, error_packets_indices)

            if no_of_fragments == 0:
                continue

            if keep_connected_daemon_status:  # if thread is running, pause it
                restore_daemon_status = True
                keep_connected_daemon_status = False
                thread.join()

            send_data(client, "f", fragment_size, filen, message, no_of_fragments, error_packets, error_packets_indices)

            if restore_daemon_status:  # if thread was running before transfer, create new one doing same thing
                keep_connected_daemon_status = True

                thread = threading.Thread(target=keep_connected_daemon_function, args=(client,))
                thread.daemon = True
                thread.start()

            continue

        elif option == "2":  # message transfer
            no_of_fragments = 0
            message = ""
            error_packets_indices = []
            # get all settings from client's input
            fragment_size, filen, message, no_of_fragments, error_packets, error_packets_indices = \
                set_transfer_settings("m", message, no_of_fragments, error_packets_indices)

            if no_of_fragments == 0:
                continue

            if keep_connected_daemon_status:  # if thread is running, pause it
                restore_daemon_status = True
                keep_connected_daemon_status = False
                thread.join()

            send_data(client, "m", fragment_size, filen, message, no_of_fragments, error_packets, error_packets_indices)

            if restore_daemon_status:  # if thread was running before transfer, create new one doing same thing
                keep_connected_daemon_status = True

                thread = threading.Thread(target=keep_connected_daemon_function, args=(client,))
                thread.daemon = True
                thread.start()
            continue

        elif option == "3":  # toggle daemon status
            if keep_connected_daemon_status:
                keep_connected_daemon_status = False
                thread.join()
            else:
                keep_connected_daemon_status = True

                thread = threading.Thread(target=keep_connected_daemon_function, args=(client,))
                thread.daemon = True
                thread.start()

        elif option == "4":  # swap host roles
            # send SWAP to server
            try:
                client.socket_.sendto(create_header_and_payload(types.index("SWAP")), client.other_host_addr_)
                client.socket_.settimeout(MEDIUM_WAIT)
                data, address = client.socket_.recvfrom(MTU)
                packet_type, pnum, pcheck, pval = unpack_message(data)
                if packet_type == types.index("SWAP"):
                    if thread:  # stop thread if its running
                        keep_connected_daemon_status = False
                        thread.join()
                    swap_t.join()
                    server_menu(client)
                    return

            except socket.timeout:
                print("[ERROR] -- Client did not respond to SWAP.")
                continue

        elif option == 'q':  # quit the program
            if thread:  # stop the thread
                keep_connected_daemon_status = False
                thread.join()

            swap_t.join()
            # send CTERM to server
            client.socket_.sendto(create_header_and_payload(types.index("CTERM")), client.other_host_addr_)
            exit(1)


# this function resembles menu for a server and its acting options
def server_menu(server):
    global keep_connected_daemon_status
    global server_input
    automatic_listening_flag = True

    # input destination directory, where files will be stored
    while True:
        dest_directory = str(input("[STR] -- Choose destination directory (\'.\' for current dir.): "))
        dest_directory = os.path.abspath(dest_directory)
        if os.path.isdir(dest_directory):
            break

    while True:
        print("\n-------------- SERVER --------------")
        print("\n# -- Choose 1 -> Continue listening\n# -- Choose 2 -> Swap host roles")
        print(f"# -- Choose 3 -> Toggle automatic listening [current status: {automatic_listening_flag}]")
        print("# -- Choose 4 -> Change destination directory\n# -- Choose q -> Quit\n")

        if automatic_listening_flag:  # toggle option input
            server_input = None
            server_input_prompt()
            # server_input = server_input_check()
        else:
            server_input = input("# -- Choice: ")  # if no automatization is on, regular input is given

        if server_input == "2":  # swap host roles
            # server.socket_.close()
            try:
                server.socket_.sendto(create_header_and_payload(types.index("SWAP")), server.other_host_addr_)
                server.socket_.settimeout(MEDIUM_WAIT)
                data, address = server.socket_.recvfrom(MTU)
                packet_type, pnum, pcheck, pval = unpack_message(data)
                if packet_type == types.index("SWAP"):
                    client_menu(server)
                    return
                else:
                    print("[ERROR] -- Client was trying to send data, SWAP suspended.")
            except socket.timeout:
                print("[ERROR] -- Client did not respond to SWAP.")
                continue

        elif server_input == "3":
            if automatic_listening_flag:
                automatic_listening_flag = False
            else:
                automatic_listening_flag = True
            continue
        elif server_input == "q":  # quit the program
            server.socket_.sendto(create_header_and_payload(types.index("CTERM")), server.other_host_addr_)
            exit(1)
        elif server_input == "1":  # continue listening to client
            pass
        elif server_input == "4":
            while True:
                dest_directory = str(input("[STR] -- Choose destination directory (\'.\' for current dir.): "))
                dest_directory = os.path.abspath(dest_directory)
                if os.path.isdir(dest_directory):
                    break
            continue
        else:
            continue

        try:  # try listening to initialization packets
            server.socket_.settimeout(LONG_WAIT)
            while True:
                data, address = server.socket_.recvfrom(MTU)
                packet_type, pnum, pcheck, pval = unpack_message(data)

                if packet_type == types.index("DPING"):  # DPING
                    print(f"[{types[packet_type]}] -- received, keeping connection to: {address}")
                    # send back acknowledgment
                    server.socket_.sendto(create_header_and_payload(types.index("DPING")), address)
                    continue

                if packet_type == types.index("CTERM"):  # CTERM
                    print(f"[{types[packet_type]}] -- received, terminating connection to: {address}")
                    while True:
                        quitopt = str(input("[STR] -- Quit server as well?[y/n]: "))  # terminate server or restart it
                        if quitopt == "y":
                            exit(1)
                        elif quitopt == "n":
                            server.socket_.close()
                            server_start()

                if packet_type == types.index("SWAP"):  # SWAP
                    print(f"[{types[packet_type]}] -- received, client at {address} requested role swap.\n")
                    server.socket_.sendto(create_header_and_payload(types.index("SWAP")), server.other_host_addr_)
                    client_menu(server)
                    return

                if packet_type == types.index("FINIT"):  # FINIT
                    print(f"[{types[packet_type]}] -- received from: {address}")
                    # send back acknowledgment
                    server.socket_.sendto(create_header_and_payload(types.index("FINIT")), address)
                    receive_data(server, "f", int(pval), dest_directory)
                elif packet_type == types.index("MINIT"):  # MINIT
                    print(f"[{types[packet_type]}] -- received from: {address}")
                    # send back acknowledgment
                    server.socket_.sendto(create_header_and_payload(types.index("MINIT")), address)
                    receive_data(server, "m", int(pval), dest_directory)

                break

        except socket.error:
            print("[ERROR] -- Socket timed out.\n")
            # server.socket_.shutdown(socket.SHUT_RDWR)
            server.socket_.close()
            return


if __name__ == "__main__":

    print("\n$ -- UDP Communicator\n$ -- Author: Marko Stahovec\n")
    while True:
        print("# -- Choose 1 -> client\n# -- Choose 2 -> server\n# -- Choose q -> quit\n")
        choice = str(input("# -- Choice: "))
        if choice == "q":  # choice for quitting a program
            exit(1)
        elif choice == "1":  # choice for starting a client
            client_start()
        elif choice == "2":  # choice for starting a server
            server_start()
        else:
            print("[ERROR] -- Incorrect input\n")
