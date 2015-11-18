from privipk.keys import *
from privipk.schnorr import SchnorrSignature
from privipk.parameters import default as DefaultParams
from charm.core.math.integer import getMod
import utils

import unittest


class EqualityTest(unittest.TestCase):
    def testParams(self):
        params1 = DefaultParams
        params2 = DefaultParams

        assert params1 == params2

        params3 = self.params3
        params4 = self.params4
        emptyParams = Params()

        assert params1 != emptyParams
        assert params2 != emptyParams
        assert params3 != emptyParams
        assert params4 != emptyParams
        assert params1 != params3
        assert params2 != params3
        assert params3 != params4
        assert params1 != params4
        assert params2 != params4

    def testSchnorrSig(self):
        sk = LongTermSecretKey(DefaultParams)
        msg = 'some random message'

        signer = sk.getSigner()
        sig1 = signer.sign(msg)
        sig2 = signer.sign(msg)
        sig3 = signer.sign(msg + 'a')
        assert sig1 == sig2
        assert sig1 != sig3

        sig4 = sk.getSigner().sign(msg)
        assert sig1 != sig4
        assert sig2 != sig4

    def testShortTermKeys(self):
        params = DefaultParams

        sts1 = ShortTermSecretKey(params)
        sts2 = ShortTermSecretKey(params, sts1.getT())
        sts3 = ShortTermSecretKey(params)
        assert sts1 == sts2
        assert sts1 != sts3
        assert sts2 != sts3

        stp1 = sts1.getPublicKey()
        stp2 = sts2.getPublicKey()
        stp3 = sts3.getPublicKey()
        assert stp1 == stp2
        assert stp1 != stp3
        assert stp2 != stp3

    def testLongTermKeys(self):
        params = DefaultParams

        lts1 = LongTermSecretKey(params)
        lts2 = LongTermSecretKey(params, lts1.getX())
        lts3 = LongTermSecretKey(params)
        assert lts1 == lts2
        assert lts1 != lts3
        assert lts2 != lts3

        ltp1 = lts1.getPublicKey()
        ltp2 = lts2.getPublicKey()
        ltp3 = lts3.getPublicKey()
        assert ltp1 == ltp2
        assert ltp1 != ltp3
        assert ltp2 != ltp3

    def _createPublicKey(self, params):
        r = params.g ** params.group.random()
        ltp = LongTermSecretKey(params).getPublicKey()
        stp = ShortTermSecretKey(params).getPublicKey()
        y_KGC = params.g ** params.group.random()
        kgcPk = LongTermPublicKey(params, y_KGC)

        return PublicKey(params, ltp, stp, r, kgcPk)

    def testPublicKey(self):
        pk1 = self._createPublicKey(DefaultParams)
        pk2 = self._createPublicKey(DefaultParams)
        assert pk1 != pk2

        pk3 = PublicKey(pk1.params, pk1.ltp, pk1.stp, pk1.r, pk1.kgcPk)
        assert pk1 == pk3

        r = self.params3.g ** self.params3.group.random()
        pk4 = PublicKey(self.params3, pk3.ltp, pk3.stp, r, pk3.kgcPk)
        assert pk4 != pk3

    def _createSecretKey(self, params):
        k_c = params.group.random()
        lts = LongTermSecretKey(params)
        sts = ShortTermSecretKey(params)
        s = params.group.random()

        return SecretKey(params, lts, sts, k_c, s)

    def testSecretKey(self):
        params = DefaultParams

        sk1 = self._createSecretKey(params)
        sk2 = self._createSecretKey(params)
        assert sk1 != sk2

        sk3 = SecretKey(sk2.params, sk2.lts, sk2.sts, sk2.k_c, sk2.s)
        assert sk2 == sk3

        sk3.k_c = sk3.k_c + sk3.k_c
        assert sk3 != sk2

    def testKeyPair(self):
        kpA = utils.genKeyPair('alice')
        kpAp = utils.genKeyPair('alice')
        kpB = utils.genKeyPair('bob')

        assert kpA != kpB
        assert kpA != kpAp
        assert kpA == kpA
        assert kpB == kpB

    p3 = integer(141946174996262808170680900915881841839688583123867198097217698455449525134913809499846201521325870119124935617487601414341575556489388761474412803854849683625328230311495386207377274919944477013053952230407903083262603438927123347708989726739617935520684934672253587382424246354910028863481178799314069385127)
    q3 = integer(70973087498131404085340450457940920919844291561933599048608849227724762567456904749923100760662935059562467808743800707170787778244694380737206401927424841812664115155747693103688637459972238506526976115203951541631301719463561673854494863369808967760342467336126793691212123177455014431740589399657034692563)
    g3 = integer(124357423156160941444299976093648401200159238429808734038734786089224168589684545864965869087562443846192250231122676656028764370899451837323388693106140650748877640182934928094816967727507318267090355981915537910182582227942394021401500913192762974924992629829898602293076848198913764429790666165473400212937) % p3
    params3 = Params(p=p3, q=q3, g=g3, num_bits=1024)

    p4 = integer(134915632604707402261991111533609468868856311180048965144427808958391639227465734467279582659518252866068719762481263470579516628747138904684579964555002095853306956743984364805695194591132543074673672836164918142138285957950799214243367737849450431152753787292521127032542474594215973288582461126674933340399)
    q4 = integer(67457816302353701130995555766804734434428155590024482572213904479195819613732867233639791329759126433034359881240631735289758314373569452342289982277501047926653478371992182402847597295566271537336836418082459071069142978975399607121683868924725215576376893646260563516271237297107986644291230563337466670199)
    g4 = integer(22190877839422839860146843628603321072895758887585613649979386520808058889947710878015142627589614173431276614694062324373632059076201679585444751588378986858285685833305696226936919888396502070352728541834119865652689858185184865206589941216332857482239486521734185375735855388573455225160642157255916834166) % p4
    params4 = Params(p=p4, q=q4, g=g4, num_bits=1024)


if __name__ == '__main__':
    unittest.main()
