import json

from charm.core.math.integer import integer, getMod, serialize, deserialize
from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.conversion import Conversion

"""
p and q are primes, s.t. p = 2q + 1.

Z_p is a group of order (cardinality) p-1, with subgroups of order 2 and q (because
p - 1 is divisible by 2 and by q only, since q is prime)

Z_q is the additive group where exponents are sampled from when generating private
keys.

G(q) is a subgroup of Z_p of order q. G(q) is NOT Z_q
"""
class Params:

    def __init__(self, p=0, q=0, g=0, num_bits=2048):
        # IntegerGroupQ seems to be used as the Schnorr subgroup of order q
        self.group = IntegerGroupQ(0)
        self.num_bits = num_bits

        # Pick or set the Z_p and Z_q groups, along with the
        # residuosity parameter 'r' of the generator 'g' of Z_q
        if (p == 0 and q != 0) or (p != 0 and q == 0):
            raise ValueError('p and q must be either both set or unset')
        else:
            self.group.p, self.group.q, self.group.r = p, q, 2
            self.p = self.group.p
            self.q = self.group.q
            self.r = self.group.r
            self.g = g;


    def generate(self, num_bits=None):
        # Passing r=2 here, even though it defaults to 2
        if num_bits is not None:
            self.num_bits = num_bits
        self.group.paramgen(self.num_bits, 2)
        self.p = self.group.p
        self.q = self.group.q
        self.r = self.group.r
        # Randomly pick a generator g for Z_q
        # g \in [0, p), g = h^2 mod p, h \in [0, p)
        self.g = self.group.randomG()

    def __str__(self):
        return str({ 'p': str(self.p), 'q': str(self.q), 'g': str(self.g), 'r': str(self.r), 'num_bits': str(self.num_bits)})

    def setParams(self, params=None):
        global default
        if params is None:
            params = default

        self.p = params.p
        self.q = params.q
        self.g = params.g
        self.group = params.group

    def groupHash(self, msg, r):
        msg = Conversion.siginput2integer(msg)
        if isinstance(r, integer) == False:
            raise TypeError("Expected r to be of type 'integer', got " +
                type(r))

        return self.group.hash(msg, r)

    def serialize(self):
        return json.dumps({
            'p': serialize(self.p),
            'q': serialize(self.q),
            'g': serialize(self.g),
            'r': str(self.r),
            'num_bits': str(self.num_bits)
        })

    @classmethod
    def unserialize(cls, data):
        params = json.loads(data)
        p = deserialize(params['p'])
        q = deserialize(params['q'])
        r = int(params['r'])
        g = deserialize(params['g'])
        num_bits = int(params['num_bits'])

        # TODO: assert num_bits is 'correctish' w.r.t. p/q/g
        ret = Params(p, q, g, num_bits)
        ret.r = r
        return ret


    def __eq__(self, other):
        return isinstance(other, self.__class__) and\
            self.group.p == other.group.p and\
            self.group.q == other.group.q and\
            self.group.r == other.group.r and\
            self.p == other.p and\
            self.q == other.q and\
            getMod(self.g) == getMod(other.g) and\
            self.g == other.g

    def __ne__(self, other):
        return not self.__eq__(other)

# p, q and g are constant for the client and server.
p = integer( 27567025973683193615305681823405702848013981966641132885048182312039522712912411975566933117244463330119760062013617312889187133241503591536188501743588341632589520133380772456832346875511354498285082143108846351267865713385611852715270851559556428996324122143917176637731428173123861600750905952101255943706643666312716759093106873289628769889481064161499703247531003114497881963365547990344461807551712592842599202536300339727346065000867747093863296402465998934655867379454462678389970266990203928961436468161590806080560914085914434953379046232560333217634936620821307914549459854890090824705548673190535895006259)

q = integer(13783512986841596807652840911702851424006990983320566442524091156019761356456205987783466558622231665059880031006808656444593566620751795768094250871794170816294760066690386228416173437755677249142541071554423175633932856692805926357635425779778214498162061071958588318865714086561930800375452976050627971853321833156358379546553436644814384944740532080749851623765501557248940981682773995172230903775856296421299601268150169863673032500433873546931648201232999467327933689727231339194985133495101964480718234080795403040280457042957217476689523116280166608817468310410653957274729927445045412352774336595267947503129)

g = integer(24589671886152143381785327700614904255118997040086314215921645102444273442891419214617519726585942679715993241133118234842748876234340808367214806419293611810108331888082720011410668183112344292242606935559503180704468228018009636632254568841130872029162043547764925968641253852043195329364660529097599505027602056617526799114589731343943600193776491020209351765412048190078766856518017819175142234561410696280448189103913007679114332957125198377296987464041162729160075574383238658712800596288120885839631267675459860146985932100755002109700310571026829332813178869116337687045026528594786483733756858658670021320669) % p

default = Params(p, q, g)

