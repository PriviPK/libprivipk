from privipk.parameters import Params, default as DefaultParams
from charm.core.math.integer import integer, getMod
import unittest
import traceback
import os

class CharmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.params = DefaultParams

    # FIXME: figure out why no reductions in integermodule.c
    def fails_testAdditionReduces(self):
        q = self.params.q
        a = (q - 1) % q
        b = (q - 2) % q
        c = a + b

        for i in range(0, 1024):
            c = c + a + b

        assert getMod(a) == q
        assert getMod(b) == q
        assert getMod(c) == q

        #print c
        #print integer(c)
        #print c % q
        #assert integer(c % q) < q
        assert integer(c) < q

    # FIXME: figure out why no reductions in integermodule.c
    def fails_testMultiplicationReduces(self):
        q = self.params.q
        a = (q - 1) % q
        b = (q - 2) % q
        c = a * b

        for i in range(0, 1024):
            c = c * a * b

        assert getMod(a) == q
        assert getMod(b) == q
        assert getMod(c) == q

        #print c
        #print integer(c)
        #print c % q
        #assert integer(c % q) < q
        assert integer(c) < q

    def testExponentiationReduces(self):
        params = self.params
        p = params.p

        for i in range(0, 16):
            x = params.group.random()
            y = (params.g ** x)
            yp = (params.g ** x) % p

            #print "g=",params.g
            #print "q=",params.q
            #print "x=",x
            #print "y=",y
            #print "yp=",yp

            assert getMod(y) == p
            assert getMod(yp) == p
            assert y == yp


if __name__ == '__main__':
    unittest.main()
