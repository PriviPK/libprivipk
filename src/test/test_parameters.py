from privipk.parameters import default as DefaultParams, Params
from charm.core.math.integer import integer, bitsize, getMod, isPrime
import unittest

class ParametersTest(unittest.TestCase):
    # runs once, no matter how many test methods
    @classmethod
    def setUpClass(cls):
        #cls.params = Params()
        #cls.params.generate()
        cls.params = DefaultParams

    def testDefaultParams(self):
        p = self.params.p
        q = self.params.q
        g = self.params.g
        assert getMod(g) == p
        assert isPrime(p)
        assert isPrime(q)
        assert p != q
        assert p == 2*q + 1
        assert bitsize(p) >= 1024
        assert bitsize(q) >= 1023

    def testHashIsModQ(self):
        r = self.params.g ** self.params.group.random()
        h = self.params.groupHash('some message', r)

        assert getMod(h) == self.params.q
        assert getMod(h) != self.params.p
