import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from utils import *
from shared.rsa_handler import RSAHandler
from shared.aes_handler import AESHandler
from shared.stream_handler import StreamHandler
from search_handler import search_messages
import argparse
import logging
import socket
import threading

client_rsa_handler = RSAHandler()
lock = threading.Lock()

logger = logging.getLogger("client")

shutdown_event = threading.Event()
other_clients_event = threading.Event()
other_clients_cache = []

server_ip = None
server_port = None


def identity_exchange(server_stream_handler):
    # obtaining server's public key
    logger.info(f"obtaining public key from {(server_ip, server_port)}")
    server_public_key = (server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE),
                         server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE))
    if not (server_public_key[0] and server_public_key[1]):
        return False

    trusted_public_keys = client_rsa_handler.read_trusted_keys_from_file()

    # trust-on-first-use model
    if server_ip in trusted_public_keys:
        if server_public_key != trusted_public_keys[server_ip]:
            return False
    else:
        client_rsa_handler.write_trusted_key_to_file(server_ip, server_public_key)

    # testing server's identity
    logger.info(f"testing identity of {(server_ip, server_port)}")
    tests, answers = client_rsa_handler.generate_remote_identity_tests(server_public_key)

    server_stream_handler.send_bytes_data(bytes_from_int(NUM_TESTS), ENCRYPTION_HEADER_VALUE)
    for i in range(NUM_TESTS):
        server_stream_handler.send_bytes_data(bytes_from_int(tests[i]), ENCRYPTION_HEADER_VALUE)

        server_answer = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
        if not server_answer:
            return False
        if server_answer != answers[i]:
            return False

    # sending client's public key
    logger.info(f"sending client's public key to {(server_ip, server_port)}")
    server_stream_handler.send_bytes_data(bytes_from_int(client_rsa_handler.public_key[0]), ENCRYPTION_HEADER_VALUE)
    server_stream_handler.send_bytes_data(bytes_from_int(client_rsa_handler.public_key[1]), ENCRYPTION_HEADER_VALUE)

    # responding to server's identity tests
    logger.info(f"responding to identity tests from {(server_ip, server_port)}")

    test_length = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    if not test_length:
        return False

    for i in range(test_length):
        test = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
        if not test:
            return False
        server_stream_handler.send_bytes_data(bytes_from_int(client_rsa_handler.decrypt(test)), ENCRYPTION_HEADER_VALUE)

    return True


def key_exchange(server_stream_handler):
    logger.info(f"performing key exchange with {(server_ip, server_port)}")
    prime = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    generator = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    foreign_key_part = server_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    if not (prime and generator and foreign_key_part):
        return False

    exponent = AESHandler.generate_key_exchange_data(False)

    server_stream_handler.send_int(pow(generator, exponent, prime), ENCRYPTION_HEADER_VALUE)

    server_stream_handler.key = (pow(foreign_key_part, exponent, prime)) & ((1 << 128) - 1)
    return True


def print_help_menu():
    print("""============================================================
broadcast - Type this command to send a message to every other client
        Then, when prompted, enter the message.

refresh other clients - Type this command to get an updated list of clients from the server.

show messages - type this command to see all past messages that you received.

show messages [NUMBER] - type this command to see the past [NUMBER] messages that you received.
        For example, you may type "show messages 3".

exit - type this command to exit the program.

help - type this command to see the help menu.
============================================================""")


def handle_server(client_socket):
    server_stream_handler = StreamHandler(client_socket)

    try:
        if identity_exchange(server_stream_handler) and key_exchange(server_stream_handler):
            threading.Thread(target=handle_server_receive, args=(server_stream_handler,), daemon=True).start()
            while not shutdown_event.is_set():
                user_input = input("What would you like to do (type \"help\" for help menu)? ")
                if user_input == "broadcast":
                    broadcast_message = input("What message would you like to send? ")
                    server_stream_handler.send_string(broadcast_message, MESSAGE_HEADER_VALUE)
                elif user_input == "refresh other clients":
                    other_clients_event.clear()
                    server_stream_handler.send_string("send_other_clients", REQUEST_HEADER_VALUE)
                    other_clients_event.wait(timeout=5)
                    print("==============================")
                    with lock:
                        if other_clients_cache:
                            for i, c in enumerate(other_clients_cache):
                                print(f"client {i}: {c[0]}:{c[1]}")
                        else:
                            print("NO OTHER CLIENTS CONNECTED")
                    print("==============================")

                elif user_input == "exit":
                    break
                elif user_input == "help":
                    print_help_menu()
                else:
                    split_user_input = user_input.split()

                    if len(split_user_input) >= 2 and split_user_input[0] == "search":
                        patterns = split_user_input[1:]

                        with lock:
                            results = search_messages(OUTPUTS_PATH + "message_log", patterns)
                        if not results:
                            print("==============================\nNO MATCHES FOUND\n==============================")
                        else:
                            for line_num, line, matches in results:
                                print("==============================")
                                print(f"Line {line_num}: {line}")
                                print(f"Matched: {matches}")
                                print("==============================")

                    elif len(split_user_input) == 3:
                        if split_user_input[0] == "show" and split_user_input[1] == "messages" and split_user_input[
                            2].isdigit():
                            num_messages = int(split_user_input[2])
                            with lock:
                                with open(OUTPUTS_PATH + "message_log", "r") as message_file:
                                    messages = message_file.readlines()
                                    for i in range(max(len(messages) - num_messages, 0), len(messages)):
                                        print("==============================")
                                        print(messages[i])
                                        print("==============================")
                    elif len(split_user_input) == 2:
                        if split_user_input[0] == "show" and split_user_input[1] == "messages":
                            with lock:
                                with open(OUTPUTS_PATH + "message_log", "r") as message_file:
                                    messages = message_file.readlines()
                                    for i in range(len(messages)):
                                        print("==============================")
                                        print(messages[i])
                                        print("==============================")
        else:
            logger.info(f"unable to complete identity or key exchange exchange with {(server_ip, server_port)}")
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as e:
        logger.error(
            "server {(server_ip, server_port)} had an error: {e}\ndisconnecting from {(server_ip, server_port)}")
    finally:
        logger.info(f"disconnecting from {(server_ip, server_port)}")


def handle_server_receive(server_stream_handler):
    while not shutdown_event.is_set():
        try:
            server_data = server_stream_handler.receive_bytes_data()
            if not server_data:
                shutdown_event.set()
                break

            server_header_value, server_bytes = server_data

            if server_header_value == REQUEST_HEADER_VALUE:
                other_clients = []
                for _ in range(int_from_bytes(server_bytes)):
                    other_clients.append((server_stream_handler.receive_string(REQUEST_HEADER_VALUE),
                                          server_stream_handler.receive_int(REQUEST_HEADER_VALUE)))
                with lock:
                    with open(OUTPUTS_PATH + "other_clients", "w") as other_clients_file:
                        for other_client in other_clients:
                            other_clients_file.write(f"{other_client[0]} {other_client[1]}\n")
                    other_clients_cache.clear()
                    other_clients_cache.extend(other_clients)
                other_clients_event.set()

            elif server_header_value == ADDRESS_HEADER_VALUE:
                port = server_stream_handler.receive_int(ADDRESS_HEADER_VALUE)
                data = server_stream_handler.receive_string(MESSAGE_HEADER_VALUE)
                with lock:
                    with open(OUTPUTS_PATH + "message_log", "a") as messages_file:
                        messages_file.write(f"{server_bytes.decode(CHARACTER_ENCODER)} - {port} - {data}\n")
        except (OSError, ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as e:
            logger.info(f"error receiving message from server: {e}")
        except Exception as e:
            logger.info(f"unexpected exception with server: {e}")


def main():
    global server_ip
    global server_port
    parser = argparse.ArgumentParser()
    parser.add_argument("--logging-level")
    parser.add_argument("-serverIP")
    parser.add_argument("-serverPORT")
    args = parser.parse_args()
    if args.logging_level == "DEBUG":
        logging.basicConfig(level=logging.DEBUG)
    elif args.logging_level == "INFO":
        logging.basicConfig(level=logging.INFO)
    elif args.logging_level == "ERROR":
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.NOTSET)

    if args.serverIP:
        server_ip = args.serverIP
    else:
        server_ip = DEFAULT_SERVER_IP
    if args.serverPORT:
        server_port = int(args.serverPORT)
    else:
        server_port = DEFAULT_SERVER_PORT

    logger.info(f"messaging client starting, connecting to server {server_ip}")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.settimeout(TIMEOUT)

    try:
        client_socket.connect((server_ip, server_port))
        client_socket.settimeout(None)
        handle_server(client_socket)
    except (ConnectionAbortedError, ConnectionRefusedError) as e:
        logger.error(f"not able to connect to server {(server_ip, server_port)}: {e}")
    except KeyboardInterrupt:
        logger.info("shutting down client")
        shutdown_event.set()
        client_socket.close()


if __name__ == "__main__":
    main()
