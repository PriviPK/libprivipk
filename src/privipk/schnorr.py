from parameters import Params
from charm.core.math.integer import getMod, serialize, deserialize

import json

class SchnorrSigner:
    def __init__(self, lts, k=None, r_hashed=None):
        self.lts = lts
        self.params = lts.getParams()

        if k is None:
            self.k = self.params.group.random()
        self.r = self.params.g ** self.k

        if r_hashed is None:
            self.r_hashed = self.r
        else:
            # FIXME: REDUCEBUG
            self.r_hashed = r_hashed % self.params.p

    def setHashedR(self, r_hashed):
        # FIXME: REDUCEBUG
        self.r_hashed = r_hashed % self.params.p

    #def getHashedR(self):
    #    return self.r_hashed

    def getR(self):
        return self.r

    def getK(self):
        return self.k

    def sign(self, m):
        e = self.params.groupHash(m, self.r_hashed)
        q = self.params.q
        k = self.k
        x = self.lts.getX()

        assert getMod(k) == q
        assert getMod(x) == q
        assert getMod(e) == q

        # FIXME: REDUCEBUG: the result is mod q, but the number is not reduced % q
        # unless we apply the % q. figure out why charm-crypto does it this way.
        s = (k + e * x) % q
        assert getMod(s) == q

        # NOTE: when r_hashed != r, this is returning r = g^k, not r_hashed
        return SchnorrSignature(self.r, s)


class SchnorrVerifier:
    def __init__(self, ltp, sig, r_hashed=None):
        self.ltp = ltp
        self.params = ltp.getParams()
        self.sig = sig

        if r_hashed is None:
            self.r_hashed = sig.getR()
        else:
            self.r_hashed = r_hashed

    def setHashedR(self, r_hashed):
        # FIXME: REDUCEBUG
        self.r_hashed = r_hashed % self.params.p

    def verify(self, m):
        p = self.params.p
        g = self.params.g
        e = self.params.groupHash(m, self.r_hashed)
        r = self.sig.getR()
        s = self.sig.getS()
        y = self.ltp.getY()

        return (r * (y ** e)) == (g ** s)

class SchnorrSignature:
    def __init__(self, r, s):
        # FIXME: REDUCEBUG
        self.r = r % getMod(r)
        self.s = s % getMod(s)

    def combine(self, sig):
        r = self.r * sig.r
        s = self.s + sig.s
        return SchnorrSignature(r, s)

    def getR(self):
        return self.r

    def getS(self):
        return self.s

    def serialize(self):
        return json.dumps({'r': serialize(self.r), 's': serialize(self.s)})

    @classmethod
    def unserialize(cls, data):
        sig = json.loads(data)

        r = deserialize(sig['r'])
        s = deserialize(sig['s'])

        return SchnorrSignature(r, s)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            self.s == other.s and\
            self.r == other.r

    def __ne__(self, other):
        return not self.__eq__(other)


