from keys import LongTermPublicKey

class Kgc:
    def __init__(self, lts):
        """
        :param lts:  the long term secret key of the KGC
        """
        self.lts = lts
        self.ltp = lts.getPublicKey()

    def getPublicKey(self):
        return self.ltp

    def signIdentity(self, r_c, m):
        signer = self.lts.getSigner()
        signer.setHashedR(r_c * signer.getR())

        sig = signer.sign(m)
        return sig
