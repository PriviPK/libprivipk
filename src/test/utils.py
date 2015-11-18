from privipk.parameters import Params, default as defaultParams
from privipk.keys import *
from privipk.kgc import Kgc

def genParams(num_bits=2048):
    params = Params(num_bits=num_bits)
    params.generate()
    return params

def genKeyPair(ident, kgc=None, params=defaultParams):
    if kgc is None:
        kgc = Kgc(LongTermSecretKey(params))

    lts = LongTermSecretKey(params)
    signer = lts.getSigner()
    r_c = signer.getR()

    svSig = kgc.signIdentity(r_c, ident)
    verifier = kgc.getPublicKey().getVerifier(svSig)
    verifier.setHashedR(r_c * svSig.getR())
    assert verifier.verify(ident) == True

    signer.setHashedR(r_c * svSig.getR())
    mySig = signer.sign(ident)

    return KeyPair.create(params, lts, kgc.getPublicKey(), signer, mySig, svSig)

