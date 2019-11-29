import rsa
import math_utils
import unittest
import sys
import secrets
import string
sys.setrecursionlimit(1500)


class WidgetTestCase(unittest.TestCase):
    def setUp(self):
        self.public_key, self.private_key = rsa.generate_key_pair(1024)

    def test_n_equal(self):
        self.assertEqual(self.public_key.n, self.private_key.n,
                         "Both keys have different Ns")

    def test_number_to_ed_eq_number(self):
        for i in range(5):
            with self.subTest():
                random_number = math_utils.mrand(1, self.public_key.n)
                result = math_utils.fexp(
                    random_number, self.public_key.e * self.private_key.d, self.public_key.n)
                self.assertEqual(random_number, result,
                                 "Number to e*d is not equal to itself mod n")

    def test_encryption_decryption(self):
        for i in range(10):
            with self.subTest():
                letters = string.ascii_lowercase
                message = ''.join(letters[secrets.randbelow(len(letters))]
                                  for i in range(50))
                cipher = rsa.encrypt(self.public_key, message)
                plain = rsa.decrypt(self.private_key, cipher)
                self.assertEqual(
                    message, plain, "Decrypted is not equal to original message")


if __name__ == '__main__':
    unittest.main()
