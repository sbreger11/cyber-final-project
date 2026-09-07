from utils import *
from shared.prime_generator import PrimeGenerator
from base64 import b64encode, b64decode
from secrets import randbelow
from math import gcd


class RSAHandler:
    def __init__(self):
        self.public_key = None
        self.private_key = None

        try:
            self.read_keys_from_files()
            if not self.probabilistic_valid_key_pair_test():
                self.public_key, self.private_key = self.generate_key_pair()
                self.write_keys_to_files()
        except (FileNotFoundError, ValueError):
            self.public_key, self.private_key = self.generate_key_pair()
            self.write_keys_to_files()

    def read_keys_from_files(self):
        with open(KEYS_PATH + "rsa_key.pub", "r") as public_key_file:
            self.public_key = (int_from_bytes(b64decode(public_key_file.readline().strip())), int_from_bytes(b64decode(
                public_key_file.readline().strip())))

        with open(KEYS_PATH + "rsa_key", "r") as key_file:
            self.private_key = (int_from_bytes(b64decode(key_file.readline().strip())), int_from_bytes(b64decode(
                key_file.readline().strip())))

    def write_keys_to_files(self):
        with open(KEYS_PATH + "rsa_key.pub", "w") as public_key_file:
            for value in self.public_key:
                public_key_file.write(b64encode(bytes_from_int(value)).decode(CHARACTER_ENCODER) + "\n")
            public_key_file.write("public key\n")

        with open(KEYS_PATH + "rsa_key", "w") as key_file:
            for value in self.private_key:
                key_file.write(b64encode(bytes_from_int(value)).decode(CHARACTER_ENCODER) + "\n")
            key_file.write("private key, DO NOT SHARE\n")

    @staticmethod
    def read_trusted_keys_from_file():
        trusted_public_keys = {}
        try:
            with open(KEYS_PATH + "trusted_keys", "r") as trusted_keys_file:
                line = trusted_keys_file.readline().strip()
                while line:
                    key_ip = line
                    public_key_int_1 = int_from_bytes(b64decode(trusted_keys_file.readline().strip()))
                    public_key_int_2 = int_from_bytes(b64decode(trusted_keys_file.readline().strip()))
                    trusted_public_keys[key_ip] = (public_key_int_1, public_key_int_2)
                    line = trusted_keys_file.readline().strip()
        except (FileNotFoundError, ValueError):
            open(KEYS_PATH + "trusted_keys", "w").close()
            return {}
        return trusted_public_keys

    @staticmethod
    def write_trusted_key_to_file(key_ip, public_key):
        with open(KEYS_PATH + "trusted_keys", "a") as trusted_keys_file:
            trusted_keys_file.write(key_ip + "\n")
            trusted_keys_file.write(b64encode(bytes_from_int(public_key[0])).decode(CHARACTER_ENCODER) + "\n")
            trusted_keys_file.write(b64encode(bytes_from_int(public_key[1])).decode(CHARACTER_ENCODER) + "\n")

    # checks the consistency of the public and private keys
    def probabilistic_valid_key_pair_test(self):
        if self.public_key[1] != self.private_key[1]:
            return False

        for i in range(NUM_TESTS):
            n = self.public_key[1]
            test_value = randbelow(n - 3) + 2
            if self.decrypt(self.encrypt(test_value)) != test_value:
                return False

        return True

    def encrypt(self, data):
        if self.public_key is None:
            return None

        return pow(data, self.public_key[0], self.public_key[1])

    def decrypt(self, encrypted_data):
        if self.private_key is None:
            return None

        return pow(encrypted_data, self.private_key[0], self.private_key[1])

    @staticmethod
    def generate_key_pair():
        while True:
            prime_1 = PrimeGenerator.probabilistically_generate_prime(PRIME_BITS, NUM_TESTS)
            prime_2 = PrimeGenerator.probabilistically_generate_prime(PRIME_BITS, NUM_TESTS)
            n = prime_1 * prime_2
            totient_of_n = (prime_1 - 1) * (prime_2 - 1)

            # checking for invalid conditions
            if prime_1 == prime_2 or gcd(PUBLIC_EXPONENT, totient_of_n) != 1:
                continue

            return (PUBLIC_EXPONENT, n), (pow(PUBLIC_EXPONENT, -1, totient_of_n), n)

    # generates tests for remote public keys
    @staticmethod
    def generate_remote_identity_tests(remote_public_key):
        tests = []
        answers = []
        for i in range(NUM_TESTS):
            test_value = randbelow(remote_public_key[1] - 3) + 2
            tests.append(pow(test_value, remote_public_key[0], remote_public_key[1]))
            answers.append(test_value)
        return tests, answers
