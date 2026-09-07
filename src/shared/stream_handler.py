from utils import *
from shared.aes_handler import AESHandler
from struct import pack, unpack


class StreamHandler:
    def __init__(self, connection):
        self.connection = connection
        self.key = None

    # receives data_size bytes of data from the stream
    def recv_all(self, data_size):
        data = bytes()
        while len(data) < data_size:
            packet = self.connection.recv(data_size - len(data))
            if not packet:
                return None
            data += packet

        return data

    # receives any kind of data from the stream
    def receive_bytes_data(self):
        header_value_bytes = self.recv_all(1)
        if header_value_bytes:
            data = bytes()

            header_value = unpack("!B", header_value_bytes)[0]
            while header_value % 2 == 0:
                header_bytes = self.recv_all(5)
                if not header_bytes:
                    return None
                header_value, data_size = unpack("!BI", header_bytes)

                packet = self.recv_all(data_size)
                if not packet:
                    return None
                if self.key:
                    packet = AESHandler.decrypt(packet, self.key)
                data += packet

            return header_value - 1, data

        return None

    def receive_int(self, header_value):
        int_data = self.receive_bytes_data()
        if not int_data:
            return None

        int_header_value, int_bytes = int_data
        if int_header_value != header_value:
            return None

        return int_from_bytes(int_bytes)

    def receive_string(self, header_value):
        string_data = self.receive_bytes_data()
        if not string_data:
            return None

        string_header_value, string_bytes = string_data
        if string_header_value != header_value:
            return None

        return string_bytes.decode(CHARACTER_ENCODER)

    def send_bytes_data(self, data, header_value):
        current_position = 0
        self.connection.sendall(pack("!B", header_value))

        while len(data) - current_position >= SOCKET_BLOCK_SIZE_BOUND:
            chunk = data[current_position: current_position + SOCKET_BLOCK_SIZE_BOUND]
            if self.key:
                chunk = AESHandler.encrypt(chunk, self.key)
            self.connection.sendall(pack("!BI", header_value, len(chunk)) + chunk)
            current_position += SOCKET_BLOCK_SIZE_BOUND

        final_chunk = data[current_position:]

        if self.key:
            final_chunk = AESHandler.encrypt(final_chunk, self.key)
        
        self.connection.sendall(pack("!BI", header_value + 1, len(final_chunk)) + final_chunk)

    def send_int(self, data, header_value):
        self.send_bytes_data(bytes_from_int(data), header_value)

    def send_string(self, data, header_value):
        self.send_bytes_data(data.encode(CHARACTER_ENCODER), header_value)
