from parameters import Params
from schnorr import SchnorrSigner, SchnorrVerifier, SchnorrSignature

from charm.core.math.integer import integer, int2Bytes, serialize,\
    deserialize, getMod
from hashlib import sha256
import json


class KeyPair:
    @classmethod
    def create(cls, params, lts, kgcPk, signer, mysig, svsig):
        assert isinstance(params, Params)
        assert isinstance(lts, LongTermSecretKey)
        assert isinstance(kgcPk, LongTermPublicKey)
        assert isinstance(signer, SchnorrSigner)
        assert isinstance(mysig, SchnorrSignature)
        assert isinstance(svsig, SchnorrSignature)

        # NOTE: The combine() call does not change 'mysig'
        jointsig = mysig.combine(svsig)

        k_c = signer.getK()
        s = jointsig.getS()
        sts = ShortTermSecretKey(params)    # generate one
        sk = SecretKey(params, lts, sts, k_c, s)

        ltp = lts.getPublicKey()
        stp = sts.getPublicKey()
        # FIXME: REDUCEBUG
        pk = PublicKey(params, ltp, stp, jointsig.getR(), kgcPk)

        return KeyPair(params, sk, pk)

    def __init__(self, params, sk, pk):
        assert isinstance(params, Params)
        assert isinstance(sk, SecretKey)
        assert isinstance(pk, PublicKey)

        self.sk = sk
        self.pk = pk
        self.sig = SchnorrSignature(pk.getR(), sk.getS())
        self.params = params


    def getPublicKey(self):
        return self.pk

    def getSecretKey(self):
        return self.sk

    def getSig(self):
        return self.sig

    def getParams(self):
        return self.params

    def serialize(self):
        return json.dumps({
            'pk': self.pk.serialize(),
            'sk': self.sk.serialize(),
        })

    @classmethod
    def unserialize(cls, params, data, ident):
        kp = json.loads(data)
        sk = SecretKey.unserialize(params, kp['sk'])
        pk = PublicKey.unserialize(params, kp['pk'])

        kp = KeyPair(params, sk, pk)

        # verify joint signature, just to check for corruption
        # FIXME: REDUCEBUG
        y = (pk.getY() * pk.getKgcY()) % params.p
        jointPk = LongTermPublicKey(params, y)
        if not jointPk.getVerifier(kp.getSig()).verify(ident):
            raise ValueError("Could not verify joint Schnorr signature on " +
                             "'" + ident + "'")

        return kp

    def deriveKey(self, otherPk, otherEmail, keyType):
        return self.sk.deriveKey(otherPk, otherEmail, keyType)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            self.pk == other.pk and\
            self.sk == other.sk and\
            self.sig == other.sig and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the (r_c, r_s, u, y_a, y_KGC)
class PublicKey:
    def __init__(self, params, ltp, stp, r, kgcPk):
        assert getMod(r) == params.p
        assert isinstance(params, Params)
        assert isinstance(ltp, LongTermPublicKey)
        assert isinstance(stp, ShortTermPublicKey)
        assert isinstance(kgcPk, LongTermPublicKey)

        self.ltp = ltp
        self.stp = stp
        self.params = params
        self.r = r
        self.kgcPk = kgcPk

    def getVerifier(self, sig):
        return self.ltp.getVerifier(sig)

    def getU(self):
        return self.stp.getU()

    def getY(self):
        return self.ltp.getY()

    def getKgcY(self):
        return self.kgcPk.getY()

    # NOTE: Returns the joint r = r_c*r_s
    def getR(self):
        return self.r

    def getParams(self):
        return self.params

    def serialize(self):
        return json.dumps({
            'ltp': self.ltp.serialize(),
            'stp': self.stp.serialize(),
            'r': serialize(self.r),
            'kgcPk': self.kgcPk.serialize()
        })

    @classmethod
    def unserialize(cls, params, data):
        pk = json.loads(data)
        return PublicKey(params,
            LongTermPublicKey.unserialize(params, pk['ltp']),
            ShortTermPublicKey.unserialize(params, pk['stp']),
            deserialize(pk['r']),
            LongTermPublicKey.unserialize(params, pk['kgcPk']))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            self.ltp == other.ltp and\
            self.stp == other.stp and\
            getMod(self.r) == getMod(other.r) and\
            self.r == other.r and\
            self.kgcPk == other.kgcPk and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the (k_c, s, t, x_a)
class SecretKey:
    def __init__(self, params, lts, sts, k_c, s):
        assert isinstance(params, Params)
        assert isinstance(lts, LongTermSecretKey)
        assert isinstance(sts, ShortTermSecretKey)
        assert getMod(s) == params.q
        assert getMod(k_c) == params.q

        self.lts = lts
        self.sts = sts
        self.params = params
        self.k_c = k_c
        self.s = s      # this is just the s from the (r,s) SchnorrSignature

    def getSigner(self):
        return self.lts.getSigner()

    def getT(self):
        return self.sts.getT()

    def getX(self):
        return self.lts.getX()

    def getS(self):
        return self.s

    def getParams(self):
        return self.params

    def deriveKey(self, otherPk, otherEmail, keyType):
        assert isinstance(otherPk, PublicKey)
        p = self.params.p

        ub = otherPk.getU()
        rB = otherPk.getR()
        yB = otherPk.getY() * otherPk.getKgcY()
        hB = self.params.groupHash(otherEmail, rB)

        ta = self.getT()
        sA = self.getS()

        # NOTE: this key-agreement (KA) will only work if signature is k + cx
        # or if public key is g^-x (unless you tweak the KA code below)
        z1 = (ub * rB * (yB ** hB))**(ta + sA)
        z2 = ub ** ta

        # FIXME: REDUCEBUG
        z1 = z1 % p
        z2 = z2 % p

        return self._hashKey(z1, z2, keyType)

    def _hashKey(self, z1, z2, keyType):
        h = sha256()
        z1bytes = int2Bytes(z1)
        z2bytes = int2Bytes(z2)

        #import binascii
        #print 'z1=', binascii.hexlify(z1bytes)
        #print 'z2=', binascii.hexlify(z2bytes)

        h.update(z1bytes)
        h.update(z2bytes)
        return h.digest()

    def serialize(self):
        return json.dumps({
            'lts': self.lts.serialize(),
            'sts': self.sts.serialize(),
            'k_c': serialize(self.k_c),
            's': serialize(self.s)
        })

    @classmethod
    def unserialize(cls, params, data):
        sk = json.loads(data)
        return SecretKey(params,
            LongTermSecretKey.unserialize(params, sk['lts']),
            ShortTermSecretKey.unserialize(params, sk['sts']),
            deserialize(sk['k_c']),
            deserialize(sk['s']))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            getMod(self.k_c) == getMod(other.k_c) and\
            self.k_c == other.k_c and\
            getMod(self.s) == getMod(other.s) and\
            self.s == other.s and\
            self.lts == other.lts and\
            self.sts == other.sts and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the 'u', computed from 't'
class ShortTermPublicKey:
    def __init__(self, params, u):
        assert isinstance(params, Params)
        assert getMod(u) == params.p

        self.params = params
        self.u = u

    def getU(self):
        return self.u

    def getParams(self):
        return self.params

    def serialize(self):
        return json.dumps({'u': serialize(self.u)})

    @classmethod
    def unserialize(cls, params, data):
        pk = json.loads(data)
        u = deserialize(pk['u'])

        return ShortTermPublicKey(params, u)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            getMod(self.u) == getMod(other.u) and\
            self.u == other.u and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the 't'
class ShortTermSecretKey:
    def __init__(self, params, t=None):
        assert isinstance(params, Params)

        self.params = params
        if t is None:
            self.t = self.params.group.random()
        else:
            assert isinstance(t, integer)
            assert getMod(t) == params.q
            self.t = t

    def getT(self):
        return self.t

    def computeU(self):
        return self.params.g ** self.t

    def getParams(self):
        return self.params

    def getPublicKey(self):
        return ShortTermPublicKey(self.params, self.computeU())

    def serialize(self):
        return json.dumps({'t': serialize(self.t)})

    @classmethod
    def unserialize(cls, params, data):
        d = json.loads(data)
        t = deserialize(d['t'])

        return ShortTermSecretKey(params, t)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            getMod(self.t) == getMod(other.t) and\
            self.t == other.t and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the 'y', computed from 'x'
class LongTermPublicKey:
    def __init__(self, params, y):
        assert isinstance(params, Params)
        assert getMod(y) == params.p

        self.params = params
        self.y = y

    def getVerifier(self, sig):
        return SchnorrVerifier(self, sig)

    def getY(self):
        return self.y

    def getParams(self):
        return self.params

    def serialize(self):
        return json.dumps({'y': serialize(self.y)})

    @classmethod
    def unserialize(cls, params, data):
        pk = json.loads(data)
        y = deserialize(pk['y'])

        return LongTermPublicKey(params, y)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            getMod(self.y) == getMod(other.y) and\
            self.y == other.y and\
            self.params == other.params

    def __ne__(self, other):
        return not self.__eq__(other)


# the 'x'
class LongTermSecretKey:
    def __init__(self, params, x=None):
        assert isinstance(params, Params)

        self.params = params
        if x is None:
            self.x = self.params.group.random()
        else:
            assert isinstance(x, integer)
            assert getMod(x) == params.q
            self.x = x

    def getSigner(self):
        return SchnorrSigner(self)

    def getX(self):
        return self.x

    def computeY(self):
        return self.params.g ** self.x

    def getParams(self):
        return self.params

    def getPublicKey(self):
        return LongTermPublicKey(self.params, self.computeY())

    def serialize(self):
        return json.dumps({'x': serialize(self.x)})

    @classmethod
    def unserialize(cls, params, data):
        d = json.loads(data)
        x = deserialize(d['x'])

        return LongTermSecretKey(params, x)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            getMod(other.x) == getMod(self.x) and\
            other.x == self.x and\
            other.params == self.params

    def __ne__(self, other):
        return not self.__eq__(other)
