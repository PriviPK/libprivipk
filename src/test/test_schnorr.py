from privipk.kgc import Kgc
from privipk.keys import LongTermSecretKey, LongTermPublicKey
from privipk.parameters import default as DefaultParams, Params
from charm.core.math.integer import integer, bitsize, getMod
import unittest
import traceback
import os

class SchnorrTest(unittest.TestCase):
    # runs before each test method
    def setUp(self):
        pass

    def tearDown(self):
        pass

    # runs once, no matter how many test methods
    @classmethod
    def setUpClass(cls):
        #cls.params = Params()
        #cls.params.generate()
        cls.params = DefaultParams

        cls.sk = LongTermSecretKey(cls.params)
        cls.pk = cls.sk.getPublicKey()

        cls.badSk = LongTermSecretKey(cls.params)
        cls.badPk = cls.badSk.getPublicKey()

    @classmethod
    def tearDownClass(cls):
        pass

    def testBasic(self):
        msg = 'some message'
        assert msg != msg[::-1] # will assume this below

        pk = self.pk
        sk = self.sk
        p = self.params.p
        q = self.params.q

        signer = sk.getSigner()
        sig = signer.sign(msg)

        # Make sure this is a non-empty signature
        assert sig.getR() is not None
        assert sig.getS() is not None
        assert signer.getK() is not None
        assert getMod(signer.getK()) == q
        assert getMod(sig.getS()) == q
        assert getMod(sig.getR()) == p
        assert sig.getR() > integer(0) % p
        assert sig.getS() > integer(0) % q
        assert signer.getK() > integer(0) % q
        assert integer(sig.getR()) < p
        print "s=",sig.getS()
        print "integer(s)=",integer(sig.getS())
        assert integer(sig.getS()) < q
        assert integer(signer.getK()) < q
        assert bitsize(sig.getR()) > 1
        assert bitsize(sig.getS()) > 1
        assert bitsize(signer.getK()) > 1
        assert (self.params.g ** signer.getK()) == sig.getR()

        # Make sure verifying the signed message succeeds
        verifier = pk.getVerifier(sig)
        assert verifier.verify(msg) == True

        # Make sure verifying a different message fails
        assert verifier.verify(msg + 'a') == False
        assert verifier.verify('b' + msg) == False
        msg = msg[::-1] # reverses string
        assert verifier.verify(msg) == False

    def testDifferentKey(self):
        msg = 'some message'
        pk = self.pk
        sk = self.sk
        badPk = self.badPk
        badSk = self.badSk

        badSigner = badSk.getSigner()
        sig = badSigner.sign(msg)

        assert pk.getVerifier(sig).verify(msg) == False
        assert badPk.getVerifier(sig).verify(msg) == True

        signer = sk.getSigner()
        sig = signer.sign(msg)

        assert badPk.getVerifier(sig).verify(msg) == False
        assert pk.getVerifier(sig).verify(msg) == True

    def testDifferentKandR(self):
        msg = 'some message'
        pk = self.pk
        sk = self.sk
        p = self.params.p

        signer = sk.getSigner()
        sig = signer.sign(msg)

        # Make sure initial verification works
        assert pk.getVerifier(sig).verify(msg) == True

        # Verify against a different r_hashed
        verifier = pk.getVerifier(sig)
        verifier.setHashedR(sig.getR() ** integer(2))
        assert verifier.verify(msg) == False

        # Verify against a different r in the signature
        sig_mod = signer.sign(msg)
        sig_mod.r = sig.getR() ** integer(42)
        verifier = pk.getVerifier(sig_mod)
        assert verifier.verify(msg) == False

        # verify against a different s in the signature
        sig_mod = signer.sign(msg)
        sig_mod.s = sig.getS() ** integer(23)
        verifier = pk.getVerifier(sig_mod)
        assert verifier.verify(msg) == False

        # verify against a different r and s in the signature
        sig_mod = signer.sign(msg)
        sig_mod.s = sig.getS() ** integer(23)
        sig_mod.r = sig.getR() ** integer(42)
        verifier = pk.getVerifier(sig_mod)
        assert verifier.verify(msg) == False

if __name__ == '__main__':
    unittest.main()
