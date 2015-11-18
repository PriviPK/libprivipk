from privipk.kgc import Kgc
from privipk.keys import LongTermSecretKey
from privipk.parameters import default as DefaultParams
import utils
import unittest


class KeyAgreementTest(unittest.TestCase):
    # runs once, no matter how many test methods
    @classmethod
    def setUpClass(cls):
        #cls.params = Params()
        #cls.params.generate()
        cls.params = DefaultParams

        cls.kgc = []
        for i in range(0, 2):
            kgc = Kgc(LongTermSecretKey(cls.params))
            cls.kgc.append(kgc)

    def testBasic(self):
        kgc = self.kgc[0]
        params = self.params

        # the client (alice), would generate this r as she
        # would also have to sign her identity
        r_c = LongTermSecretKey(params).getSigner().getR()

        sig = kgc.signIdentity(r_c, "alice")

        # wrong r used in hash
        verifier = kgc.getPublicKey().getVerifier(sig)
        assert not verifier.verify("alice")

        # right r used in hash
        verifier = kgc.getPublicKey().getVerifier(sig)
        verifier.setHashedR(r_c * sig.getR())
        assert verifier.verify("alice")

    def testSameKgc(self):
        self._testKeyAgreement(self.kgc[0], self.kgc[0])

    def testDifferentKgc(self):
        self.assertNotEqual(self.kgc[0].getPublicKey(), self.kgc[1].getPublicKey())
        self._testKeyAgreement(self.kgc[0], self.kgc[1])

    def _testKeyAgreement(self, kgcA, kgcB):
        keyType = 'aead'
        alice = 'alice@wonderland.com'
        bob = 'bob@bobworld.org'
        charlie = 'charlie@character.us'

        keypairA = utils.genKeyPair(alice, kgcA, DefaultParams)
        keypairB = utils.genKeyPair(bob, kgcB, DefaultParams)
        keypairC = utils.genKeyPair(charlie, kgcA, DefaultParams)

        symkeyAB = keypairA.deriveKey(keypairB.getPublicKey(), bob, keyType)
        symkeyBA = keypairB.deriveKey(keypairA.getPublicKey(), alice, keyType)
        symkeyAC = keypairA.deriveKey(keypairC.getPublicKey(), charlie, keyType)
        symkeyBC = keypairB.deriveKey(keypairC.getPublicKey(), charlie, keyType)

        assert symkeyAB == symkeyBA
        assert symkeyAC != symkeyAB
        assert symkeyBC != symkeyAB
        assert symkeyAC != symkeyBC


if __name__ == '__main__':
    unittest.main()
