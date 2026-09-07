import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from utils import *
from shared.rsa_handler import RSAHandler
from shared.aes_handler import AESHandler
from shared.stream_handler import StreamHandler
import argparse
import logging
import socket
import threading

server_rsa_handler = RSAHandler()
lock = threading.Lock()

logger = logging.getLogger("server")

clients = {}
client_send_locks = {}
client_threads = {}
shutdown_event = threading.Event()


def identity_exchange(client_stream_handler, client_address):
    # sending server's public key
    logger.info(f"sending server's public key to {client_address}")
    client_stream_handler.send_int(server_rsa_handler.public_key[0], ENCRYPTION_HEADER_VALUE)
    client_stream_handler.send_int(server_rsa_handler.public_key[1], ENCRYPTION_HEADER_VALUE)

    # responding to client's identity tests
    logger.info(f"responding to identity tests from {client_address}")
    test_length = client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    if not test_length:
        return False

    for i in range(test_length):
        test = client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
        if not test:
            return False

        logger.debug(f"test {i} from {client_address}: test= {test}, answer= {server_rsa_handler.decrypt(test)}")
        client_stream_handler.send_int(server_rsa_handler.decrypt(test), ENCRYPTION_HEADER_VALUE)

    # obtaining client's public key
    logger.info(f"obtaining public key from {client_address}")
    client_public_key = (client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE),
                         client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE))
    if not (client_public_key[0] and client_public_key[1]):
        return False

    trusted_public_keys = server_rsa_handler.read_trusted_keys_from_file()

    # trust-on-first-use model
    if client_address[0] in trusted_public_keys:
        if client_public_key != trusted_public_keys[client_address[0]]:
            return False
    else:
        server_rsa_handler.write_trusted_key_to_file(client_address[0], client_public_key)

    # testing client's identity
    logger.info(f"testing identity of {client_address}")
    tests, answers = server_rsa_handler.generate_remote_identity_tests(client_public_key)

    client_stream_handler.send_int(NUM_TESTS, ENCRYPTION_HEADER_VALUE)
    for i in range(NUM_TESTS):
        client_stream_handler.send_int(tests[i], ENCRYPTION_HEADER_VALUE)

        client_answer = client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
        if not client_answer:
            return False
        if client_answer != answers[i]:
            return False

    return True


def key_exchange(client_stream_handler, client_address):
    logger.info(f"performing key exchange with {client_address}")
    prime, generator, exponent = AESHandler.generate_key_exchange_data(True)

    client_stream_handler.send_int(prime, ENCRYPTION_HEADER_VALUE)
    client_stream_handler.send_int(generator, ENCRYPTION_HEADER_VALUE)
    client_stream_handler.send_int(pow(generator, exponent, prime), ENCRYPTION_HEADER_VALUE)

    foreign_key_part = client_stream_handler.receive_int(ENCRYPTION_HEADER_VALUE)
    if not foreign_key_part:
        return False

    client_stream_handler.key = (pow(foreign_key_part, exponent, prime)) & ((1 << 128) - 1)
    return True


def send_other_clients(client_stream_handler, client_address):
    logger.info(f"sending client list to {client_address}")
    other_clients = {}
    with lock:
        for other_client_address in clients:
            if other_client_address != client_address:
                other_clients[other_client_address] = clients[other_client_address]

    with client_send_locks[client_address]:
        client_stream_handler.send_int(len(other_clients), REQUEST_HEADER_VALUE)
        for other_client_address in other_clients:
            client_stream_handler.send_string(other_client_address[0], REQUEST_HEADER_VALUE)
            client_stream_handler.send_int(other_client_address[1], REQUEST_HEADER_VALUE)

# def message(other_client_address, client_address, data):
#     logger.info(f"sending message {data} from {client_address} to {other_client_address}")
#     try:
#         with lock:
#             other_client_stream_handler = clients[other_client_address]

#         other_client_stream_handler.send_string(client_address[0], ADDRESS_HEADER_VALUE)
#         other_client_stream_handler.send_int(client_address[1], ADDRESS_HEADER_VALUE)
#         other_client_stream_handler.send_string(data, MESSAGE_HEADER_VALUE)
#     except KeyError:
#         logger.error(f"message recipient {other_client_address} not found for the message from {client_address}")
#     except (ConnectionResetError, BrokenPipeError):
#         logger.error(f"message recipient {other_client_address} had an error for the message from {client_address}")


def broadcast(client_address, data):
    logger.info(f"sending message {data} from {client_address}")
    other_clients = {}
    with lock:
        for other_client_address in clients:
            if other_client_address != client_address:
                other_clients[other_client_address] = clients[other_client_address]

    for other_client_address in other_clients:
        try:
            send_lock = client_send_locks.get(other_client_address)
            if send_lock is None:
                continue
            with send_lock:
                other_clients[other_client_address].send_string(client_address[0], ADDRESS_HEADER_VALUE)
                other_clients[other_client_address].send_int(client_address[1], ADDRESS_HEADER_VALUE)
                other_clients[other_client_address].send_string(data, MESSAGE_HEADER_VALUE)
        except (ConnectionResetError, BrokenPipeError):
            logger.error(f"message recipient {other_client_address} had an error for the message from {client_address}")


def handle_client(client_connection, client_address):
    client_stream_handler = StreamHandler(client_connection)

    try:
        logger.info(f"performing identity exchange with {client_address}")
        if identity_exchange(client_stream_handler, client_address) and key_exchange(client_stream_handler,
                                                                                     client_address):
            logger.info(f"identity and key exchange with {client_address} completed successfully")
            with lock:
                clients[client_address] = client_stream_handler
                client_send_locks[client_address] = threading.Lock()

            while not shutdown_event.is_set():
                logger.info(f"listening from {client_address}")
                client_data = client_stream_handler.receive_bytes_data()
                if not client_data:
                    break

                client_header_value, client_bytes = client_data
                if client_header_value == REQUEST_HEADER_VALUE:
                    if client_bytes.decode(CHARACTER_ENCODER) == "send_other_clients":
                        send_other_clients(client_stream_handler, client_address)

                # elif client_header_value == ADDRESS_HEADER_VALUE:
                #     other_client_ip = client_bytes.decode(CHARACTER_ENCODER)
                #     other_client_port = client_stream_handler.receive_int(ADDRESS_HEADER_VALUE)
                #     if not other_client_port:
                #         break

                #     other_client_address = (other_client_ip, other_client_port)
                #     client_message = client_stream_handler.receive_string(MESSAGE_HEADER_VALUE)
                #     if not client_message:
                #         break

                #     message(other_client_address, client_address, client_message)
                elif client_header_value == MESSAGE_HEADER_VALUE:
                    broadcast(client_address, client_bytes.decode(CHARACTER_ENCODER))
        else:
            logger.info(f"unable to complete identity or key exchange exchange with {client_address}")
    except (OSError, ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as e:
        logger.error(f"client {client_address} had an error: {e}")
    except Exception as e:
        logger.error(f"unexpected exception with {client_address}: {e}")
    finally:
        logger.info(f"disconnecting from {client_address}")
        with lock:
            if client_address in clients:
                del clients[client_address]

            if client_address in client_send_locks:
                del client_send_locks[client_address]

            del client_threads[client_address]

        client_connection.close()


def main():
    global NETWORK_INTERFACE

    parser = argparse.ArgumentParser()
    parser.add_argument("--logging-level")
    parser.add_argument("--network-interface")
    args = parser.parse_args()
    if args.logging_level == "DEBUG":
        logging.basicConfig(level=logging.DEBUG)
    elif args.logging_level == "INFO":
        logging.basicConfig(level=logging.INFO)
    elif args.logging_level == "ERROR":
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.NOTSET)
    if args.network_interface == "local":
        NETWORK_INTERFACE = "127.0.0.1"
    elif args.network_interface == "public":
        NETWORK_INTERFACE = "0.0.0.0"
    logger.info(f"messaging server starting on port {PORT}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((NETWORK_INTERFACE, PORT))
    server_socket.settimeout(TIMEOUT)
    server_socket.listen()

    try:
        while True:
            try:
                client_connection, client_address = server_socket.accept()
                logger.info(f"connecting to {client_address}")

                client_threads[client_address] = threading.Thread(target=handle_client, args=(client_connection,
                                                                                              client_address), daemon=True)
                client_threads[client_address].start()
            except socket.timeout:
                pass
            except (ConnectionAbortedError, ConnectionRefusedError) as e:
                logger.error(f"not able to connect to client: {e}")
    except KeyboardInterrupt:
        logger.info("shutting down messaging server")
        shutdown_event.set()
        server_socket.close()


if __name__ == "__main__":
    main()
