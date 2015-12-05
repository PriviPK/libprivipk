The protocol
------------

Actors: _Email users_ with accounts hosted by _service providers_ and _KGC_'s 
who sign keys.

### Protocol for obtaining a signed public key


    All users and the KGC agree on public parameters: p, q and g
    ( p = 2q + 1)
    All users know KGC's public key y_KGC
    (should work with more than one KGC too)

    KGC setup
    ---------
    KGC generates keypair
    x_KGC <-- random
    y_KGC <-- g^x_KGC

    Alice setup
    -----------
    Alice registers for a Gmail address
    Alice gets 'alice@gmail.com' with a password 'pass' that only Alice knows

    Alice                                           KGC
    -----                                           ---
    generates a keypair <x_a, y_a>                      
    x_a <-- KDF(pass) or randomly generated
    y_a <-- g^x_a
    k_c <-- random % q
    r_c <-- g^k_c % p

                       r_c, id = alice@gmail.com
                    ------------------------------>
                                                    
                                                    k_s <-- random % q
                                                    r_s <-- g^k_s % p
                                                    r <-- r_s * r_c
                                                    ( r == g^(k_s + k_c) )
                                                    
                                                    # one-Schnorr sign
                                                    # sign(id, k_s, r)
                                                    e = hash(id, r)
                                                    s_s = (k_s - x_KGC*e) % q

                               s_s, r_s
                    <------------------------------

    r = r_c * r_s
    ( r == g^(k_s + k_c) )
    e = hash(id, r)

    # verify one-Schnorr sign
    # verify(id, r_s, e, s_s)
    Is 'g^s_s * y_KGC^e' equal to 'r_s'? <=>
    Is 'g^(k_s - x_KGC*e) * g^(x_KGC*e)' equal to 'g^k_s' <=>
    Is 'g^(k_s) == g^(k_s)' ??

    # two-Schnorr sign
    s_c = (k_c - x_a*e) % q

    s = (s_c + s_s) % q
      = ((k_c + k_s) - (x_a + x_KGC)*e) % q

    # no need to verify the two-Schnorr since we're just
    # adding our own user-produced data (might want to check it just
    # for corruption)
    
    u <-- random % q
    t <-- g^u % p

    pk_a <-- (r_c, r_s, u, y_a, y_KGC)    # r_c, NOT r
    sk_a <-- (k_c, s, t, x_a)


                   publish (r_c, r_s, u, y_a, y_KGC) in DHT
                    ------------------------------>

### Protocol for obtaining shared key

    Bob's keypair:
        private: (k_b, s_B, t_b, x_b)
        public:  (r_b, r_bs, u_b, y_b, y_KGCb)
            we denote y_B = y_b * y_KGCb
            we denote r_B = r_b * r_bs

    Alice's keypair:
        private: (k_a, s_A, t_a, x_a)
        public:  (r_a, r_as, u_a, y_a, y_KGCa)
            we denote y_A = y_a * y_KGCa
            we denote r_A = r_a * r_as

    Alice obtains Bob's public key securely.
    Bob obtains Alice's public key securely.

    Alice derives:
        z1 = ( u_b * r_B * (y_B)^H("bob@gmail.com", r_B) )^(t_a + s_A)
        z2 = u_b ^ t_a

    Bob derives:
        z1 = ( u_a * r_A * (y_A)^H("alice@gmail.com", r_A) )^(t_b + s_B)
        z2 = u_a ^ t_b

    Note that:
        z1 = (g^(t_a + s_A))^(t_b + s_B) = g^((t_a + s_A)*(t_b + s_B))
        z2 = u_a ^ t_b = u_b ^ t_a = g^(t_a * t_b)


Abstractions
------------

 - `KeyPair`
    - `SecretKey`
       + `ShortTermSecretKey` -- `t`
       + `LongTermSecretKey` -- `x`
       + `k_c`, `s`
       + `getSigner()`
       + `serialize() --> returns a string`
       + `unserialize(str) --> returns a SecretKey`
    - `PublicKey`
       + `ShortTermPublicKey` -- `u = g^t`
       + `LongTermPublicKey` -- `y = g^x`
       + `r_c, r_s`
       + `getVerifier(sig)`
       + `serialize() --> returns a string`
       + `unserialize(str) --> returns a PublicKey`
    - `SchnorrSignature` -- has `r=r_c*r_s` and `s=k_c + k_s + h(m, r)*(x+x_KGC)`
    - `getPublicKey()`
    - `getSecretKey()`
    - `getSigner()`
    - `getVerifier(sig)`
    - `serialize()` and `unserialize(str)`
    - `deriveSymKey(type)`
 - `SchnorrSigner`
    + `__init__(lts, k = random(), r_hashed = None)`
    + `setHashedR(r) --> sets the r used in h(m, r)`
    + `sign(m) --> computes s = k + h(m, r_hashed)*x`, returns `(r, s)`
    + `getR() --> computes, caches and returns r = g^k`
    + `getK()`
 - `SchnorrVerifier`
    + `__init__(ltp, sig, r_hashed = None)`
      - where `sig` is a `SchnorrSignature`
    + `setHashedR(r) --> sets the r used in h(m, r)`
    + `verify(m) --> verifies g^s == r * y^h(m, r_hashed)`
 - `SchnorrSignature`
    + `combine(sig)`
    + `r`, `r_hashed`, `m` (optional)
    + `getR()`, `getS()`
    + `serialize()` and `unserialize()`
 - `KgcClient`
    + `getPublicKey() --> returns y_KGC = g^x_KGC`
    + `signKeyRequestRpc(clientSig)`
 - `KgcServer`
    + `signKeyRequest(r_c, email_addr)`

Operations
----------

### Generating a key pair jointly with the KGC:

    params = readFromConfig(...)
    myInfo = readFromConfig(...)    // my email address
    kgcInfo = readFromConfig(...)   // KGC's public key fingerprint

    kgc = new KgcClient(kgcInfo)
    kgc_ltp = kgc.getPublicKey()

    my_lts = new LongTermSecretKey(params)

    my_signer = my_lts.getSigner()

    // sends an RPC, requesting a joint signature on my email address with r = r_c * r_s, where
    // r_c is generated by me and r_s is generated by the KGC
    svSig = kgc.jointSignatureRequestRpc(my_signer, myInfo.getEmail())

        //  client's jointSignatureRequestRpc(my_signer, m):
        //      r_c = my_signer.getR()
        //      svSig = makeRpcCall("jointSignatureRequest", r_c, m)
        //      return sv_sig
        //
        //  server's jointSignatureRequest(r_c, m)
        //      kgc_sk = ...
        //      signer = kgc_sk.getSigner()
        //      signer.setHashedR(r_c * signer.getR())
        //      svSig = signer.sign(m)
        //      return svSig        // returns (r_s, s_s)

    // svSig now has the k_s + h(id, r)*x_KGC set

    // must verify server's signature
    r_s = svSig.getR()
    r_c = my_signer.getR()
    r = r_s * r_c
    verifier = kgc_ltp.getVerifier(svSig)
    verifier.setHashedR(r)
    verifier.verify(myInfo.getEmail())
    
    // compute my own signature
    my_signer.setHashedR(r)
    mySig = my_signer.sign(myInfo.getEmail())
    // mySig now has the k_c + h(id, r)*x

    // should generate ShortTermKeyPair stk
    my_kp = KeyPair.create(params, my_lts, kgc_ltp, my_signer, mySig, svSig)
        //
        //  jointSig = mySig.combine(svSig)
        //  // jointSig now has k_c + k_s + h(id, r)*(x + x_KGC)

    pkdir = ...
    pkdir.publish(my_kp.getPublicKey().serialize())
    db = ...
    db.save(my_kp.serialize())

### Unserializing keypair

    keypair = KeyPair.unserialize(db.getKeyPair(...))


### Publishing your public key

    keypair = KeyPair.unserialize(db.getKeyPair(...))
    pk = keypair.getPublicKey()
    pkdir.publish(pk.serialize())

### Deriving a key

    my_keypair = db.getKeyPair(..)

    their_pk = pkdir.lookupPK("alice@wonderland.com")   // unserializes PK

    // TODO: no way to verify PK against email address, how do I make sure I got
    // the right public key? If I got the wrong public key, can the recipient
    // of the message derive the same key if he knows who i sent the email to? No.
    // that would break the security.

    symkey = my_keypair.deriveKey(theirPk, "alice@wonderland.com", keyType="aead")


### Encrypting & MACing a message

First, see "Deriving a key" above.

    symkey = ... // see "Deriving a key" above

    message = get_draft_email(...)

    enc = encrypt_and_mac(message, symkey)

    send(message)

Similar for decrypting & verifying MAC

### Signing a message (non-repudiable signature) with your LTK

    keypair = db.getKeyPair()

    message = get_draft_email(...)

    // might encrypt message here, or might not
    message = encrypt_and_mac(...)

    signer = keypair.getSecretKey().getSigner()
    sig = signer.sign(m)

Verifier would do:

    message = receiveEmail(...)

    their_pk = pkdir.lookupPK("alice@wonderland.com")
        // TODO: need to verify PK against KGC

    sig = message.getSignature()

    verifier = their_pk.getVerifier(sig)
    verifier.verify(message.getText())

IntegerGroupQ
-------------

This implements the Schnorr group `G(q)` of order (size) `q` used in the Schnorr
signature. `G(q)` ends up being a subset of `Z_p` (but is not `Z_q`)

The implementation finds primes `p,q` such that `p = 2q+1` and sets a parameter
`r` which seems to be any integer >= 2. `r` defaults to 2.

Then, it finds a generator `g` for `G(q)` by picking a random `h \in Z_p` and
letting `g = h^r % p` as long as `g != 1`

The class also provides a _bad_ `hashInt` method that can hash any arbitrary length
integer (or integers) to an element in `Z_q` (not `Z_p`, not `G(q)`).

The class's `random` method which returns an integer in `[0, q)` suggests that 
the `G(q)` group is `Z_q`, but that's not the case at all: `G(q)` will be a subset
of `Z_p`, but not `Z_q`.

I think the random method was just useful for generating exponents that can
be used with the generator `g` to create members in `G(q)`.
