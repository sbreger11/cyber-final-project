from utils import *
from secrets import randbelow, randbits


class PrimeGenerator:
    @classmethod
    def probabilistically_generate_prime(cls, bits, num_tests):
        candidate = randbits(bits) | (1 << (bits - 1)) | 1
        while not cls.probabilistic_primality_test(candidate, num_tests):
            candidate += 2

        return candidate

    # returns true if candidate is a likely prime and false if candidate is a composite
    @staticmethod
    def probabilistic_primality_test(candidate, num_tests):
        # quickly eliminating most candidates
        for small_prime in SMALL_PRIMES:
            if candidate == small_prime:
                return True
            if candidate % small_prime == 0:
                return False

        # calculating the odd part and the v2 of candidate - 1
        order_odd_part = candidate - 1
        order_v2 = 0
        while order_odd_part % 2 == 0:
            order_odd_part //= 2
            order_v2 += 1

        for i in range(num_tests):
            # choosing a nonzero, non pm1 test value mod candidate
            test_value = randbelow(candidate - 3) + 2

            # applying the Miller-Rabin primality test
            strong_probable_prime = False
            current_result = pow(test_value, order_odd_part, candidate)

            if current_result == 1:
                strong_probable_prime = True

            for j in range(order_v2):
                if current_result == candidate - 1:
                    strong_probable_prime = True
                current_result = pow(current_result, 2, candidate)

            if not strong_probable_prime:
                return False

        return True

print(PrimeGenerator.probabilistically_generate_prime(1024, 40))