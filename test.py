import rsa
import math_utils
import unittest
import sys
sys.setrecursionlimit(1500)


class WidgetTestCase(unittest.TestCase):
    def setUp(self):
        self.public_key, self.private_key = rsa.generate_key_pair()

    def test_n_equal(self):
        self.assertEqual(self.public_key.n, self.private_key.n,
                         "Both keys have different Ns")

    def test_number_to_ed_eq_number(self):
        for i in range(100):
            random_number = math_utils.mrand(1, self.public_key.n)
            result = math_utils.fexp(
                random_number, self.public_key.exp * self.private_key.exp, self.public_key.n)
            self.assertEqual(random_number, result,
                             "Number to e*d is not equal to itself mod n")


if __name__ == '__main__':
    unittest.main()
