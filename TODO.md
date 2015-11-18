When receiving members of groups like `r_c \in G(q)`, check that they are
actually in `G(q)` by checking if `r_c^q == 1 (mod p)` (see "Proactive Two-Party
Signatures for User Authentication" paper, page 5, "Signature generation")

Do not use fixed `p,q,g` parameterization.

Make sure we don't use small p's and q's!

 - default size is 2048 bits
 - make sure application code cannot use smaller than 2048 bit primes

Not sure about serialization security: what can someone do if they tamper with the serialized data?

[DONE] Serialization

 - JSON?
 - [MessagePack](http://msgpack.org/)

[DONE] Make sure that if g \in IntegerGroupQ and x is group.random() (or any number
from 0 to q) then g ** x is in IntegerGroupQ? (ie is mod p, but in G(q))

 - this is **TRUE**
 - this is **FALSE** when doing `g^x` instead of `g**x`: 

Example:

    >>> g = DefaultParams.g
    >>> x = DefaultParams.group.random()
    >>> print getMod(g)
    156816585111264668689583680968857341596876961491501655859473581156994765485015490912709775771877391134974110808285244016265856659644360836326566918061490651852930016078015163968109160397122004869749553669499102243382571334855815358562585736488447912605222780091120196023676916968821094827532746274593222577067
    >>> print getMod(x)
    78408292555632334344791840484428670798438480745750827929736790578497382742507745456354887885938695567487055404142622008132928329822180418163283459030745325926465008039007581984054580198561002434874776834749551121691285667427907679281292868244223956302611390045560098011838458484410547413766373137296611288533
    >>> print getMod(g ** x)
    156816585111264668689583680968857341596876961491501655859473581156994765485015490912709775771877391134974110808285244016265856659644360836326566918061490651852930016078015163968109160397122004869749553669499102243382571334855815358562585736488447912605222780091120196023676916968821094827532746274593222577067
    >>> print getMod(g ^ x)
    0


[DONE] Client needs to verify that:

 - their r value
 - their ID
 - the server's public key

...are all in the response to `keygen(r_c, id_c)`
