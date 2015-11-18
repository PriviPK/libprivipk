from privipk.keys import *
from privipk.schnorr import SchnorrSignature
from privipk.parameters import default as DefaultParams
from charm.core.math.integer import getMod
import utils

import unittest


class SerializableTest(unittest.TestCase):

    def testParams(self):
        p1 = DefaultParams
        p2 = Params.unserialize(p1.serialize())

        self.assertEquals(p1, p2)

    def testSchnorrSig(self):
        sk = LongTermSecretKey(DefaultParams)
        signer = sk.getSigner()
        sig = signer.sign('some random message')

        s = sig.serialize()
        sig2 = SchnorrSignature.unserialize(s)

        assert getMod(sig.getR()) == getMod(sig2.getR())
        assert getMod(sig.getS()) == getMod(sig2.getS())
        assert sig2.getR() == sig.getR()
        assert sig2.getS() == sig.getS()
        assert sig == sig2

    def testShortTermKeys(self):
        params = DefaultParams
        sts1 = ShortTermSecretKey(params)
        stp1 = sts1.getPublicKey()

        sts2 = ShortTermSecretKey.unserialize(params, sts1.serialize())
        stp2 = ShortTermPublicKey.unserialize(params, stp1.serialize())

        assert getMod(sts2.getT()) == params.q
        assert getMod(stp2.getU()) == params.p
        assert sts1.getT() == sts2.getT()
        assert stp1.getU() == stp2.getU()
        assert stp1 == stp2
        assert sts1 == sts2

        # NOTE: Uncomment these tests if you add signatures to short term keys
        #msg1 = 'msg1'
        #msg2 = 'msg2'
        #signer1 = sts1.getSigner()
        #signer2 = sts2.getSigner()

        #sig1 = signer1.sign(msg1)
        #sig2 = signer2.sign(msg2)

        #assert stp1.getVerifier(sig1).verify(msg1) == True
        #assert stp1.getVerifier(sig2).verify(msg2) == True
        #assert stp2.getVerifier(sig1).verify(msg1) == True
        #assert stp2.getVerifier(sig2).verify(msg2) == True

    def testLongTermKeys(self):
        params = DefaultParams
        lts1 = LongTermSecretKey(params)
        ltp1 = lts1.getPublicKey()

        lts2 = LongTermSecretKey.unserialize(params, lts1.serialize())
        ltp2 = LongTermPublicKey.unserialize(params, ltp1.serialize())

        assert getMod(lts2.getX()) == params.q
        assert getMod(ltp2.getY()) == params.p
        assert lts1.getX() == lts2.getX()
        assert ltp1.getY() == ltp2.getY()
        assert lts1 == lts2
        assert ltp1 == ltp2

        msg1 = 'msg1'
        msg2 = 'msg2'
        signer1 = lts1.getSigner()
        signer2 = lts2.getSigner()

        sig1 = signer1.sign(msg1)
        sig2 = signer2.sign(msg2)

        assert ltp1.getVerifier(sig1).verify(msg1) == True
        assert ltp1.getVerifier(sig2).verify(msg2) == True
        assert ltp2.getVerifier(sig1).verify(msg1) == True
        assert ltp2.getVerifier(sig2).verify(msg2) == True

    def testPublicKey(self):
        params = DefaultParams
        r = params.g ** params.group.random()
        ltp = LongTermSecretKey(params).getPublicKey()
        stp = ShortTermSecretKey(params).getPublicKey()
        y_KGC = params.g ** params.group.random()
        kgcPk = LongTermPublicKey(params, y_KGC)

        pk1 = PublicKey(params, ltp, stp, r, kgcPk)
        pk2 = PublicKey.unserialize(params, pk1.serialize())

        assert getMod(pk2.getR()) == params.p
        assert pk2.getR() == pk1.getR()
        assert pk2.getU() == pk1.getU()
        assert pk2.getY() == pk1.getY()
        assert pk2.getKgcY() == pk1.getKgcY()
        assert pk2.getParams().g == pk1.getParams().g
        assert pk2.getParams().p == pk1.getParams().p
        assert pk2.getParams().q == pk1.getParams().q
        assert pk1 == pk2


    def testSecretKey(self):
        params = DefaultParams
        k_c = params.group.random()
        lts = LongTermSecretKey(params)
        sts = ShortTermSecretKey(params)
        s = params.group.random()

        sk1 = SecretKey(params, lts, sts, k_c, s)
        sk2 = SecretKey.unserialize(params, sk1.serialize())

        assert getMod(sk2.k_c) == params.q
        assert getMod(sk2.getS()) == params.q
        assert sk2.s == s
        assert sk2.k_c == k_c
        assert sk2.getX() == sk1.getX()
        assert sk2.getT() == sk1.getT()
        assert sk2.getS() == sk1.getS()
        assert sk2.getParams().g == sk1.getParams().g
        assert sk2.getParams().p == sk1.getParams().p
        assert sk2.getParams().q == sk1.getParams().q
        assert sk1 == sk2

    def testKeyPair(self):
        params = DefaultParams

        kpA1 = utils.genKeyPair('alice')
        kpB1 = utils.genKeyPair('bob')

        kpA2 = KeyPair.unserialize(params, kpA1.serialize(), 'alice')
        kpB2 = KeyPair.unserialize(params, kpB1.serialize(), 'bob')

        with self.assertRaises(ValueError):
            KeyPair.unserialize(params, kpA1.serialize(), 'bad name here')

        assert kpA1 != kpB1
        assert kpA2 != kpB2
        assert kpA1 == kpA2
        assert kpB1 == kpB2


if __name__ == '__main__':
    unittest.main()
