from binascii import hexlify
from functools import wraps, reduce
from hashlib import sha256
from typing import Tuple


def crt(n, a):
    """
    Compute the unique solution of a set of congruences via the Chinese Remainder
    Theorem.
    `n` should be a list of pairwise coprime modulos, `a` should be a list of residues.
    """
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * int(Mod(p, n_i).inverse()) * p
    return sum % prod


def extgcd(a, b):
    """
    Perform the extended Euclid's algorithm, and return the coefficients
    for Bezout's equality and the gcd of `a` and `b`.
    (Not interesting)
    """
    if abs(b) > abs(a):
        (x, y, d) = extgcd(b, a)
        return y, x, d

    if abs(b) == 0:
        return 1, 0, a

    x1, x2, y1, y2 = 0, 1, 1, 0
    while abs(b) > 0:
        q, r = divmod(a, b)
        x = x2 - q * x1
        y = y2 - q * y1
        a, b, x2, x1, y2, y1 = b, r, x1, x, y1, y

    return x2, y2, a


def check(func):
    """Automatic type check and upcast for the `Mod` class. (Not interesting)"""

    @wraps(func)
    def method(self, other):
        if type(self) is not type(other):
            other = self.__class__(other, self.n)
        else:
            if self.n != other.n:
                raise ValueError
        return func(self, other)

    return method


class Mod(object):
    """ℤ_n class. (Not interesting but useful)"""

    def __init__(self, x: int, n: int):
        self.x: int = x % n
        self.n: int = n

    @check
    def __add__(self, other):
        return Mod((self.x + other.x) % self.n, self.n)

    @check
    def __radd__(self, other):
        return self + other

    @check
    def __sub__(self, other):
        return Mod((self.x - other.x) % self.n, self.n)

    @check
    def __rsub__(self, other):
        return -self + other

    def __neg__(self):
        return Mod(self.n - self.x, self.n)

    def inverse(self):
        x, y, d = extgcd(self.x, self.n)
        return Mod(x, self.n)

    def __invert__(self):
        return self.inverse()

    @check
    def __mul__(self, other):
        return Mod((self.x * other.x) % self.n, self.n)

    @check
    def __rmul__(self, other):
        return self * other

    @check
    def __truediv__(self, other):
        return self * ~other

    @check
    def __rtruediv__(self, other):
        return ~self * other

    @check
    def __floordiv__(self, other):
        return self * ~other

    @check
    def __rfloordiv__(self, other):
        return ~self * other

    @check
    def __div__(self, other):
        return self.__floordiv__(other)

    @check
    def __rdiv__(self, other):
        return self.__rfloordiv__(other)

    @check
    def __divmod__(self, divisor):
        q, r = divmod(self.x, divisor.x)
        return Mod(q, self.n), Mod(r, self.n)

    def __int__(self):
        return self.x

    def __bytes__(self):
        return self.x.to_bytes(length=(self.n.bit_length() + 7) // 8, byteorder="big")

    def __repr__(self):
        return str(self.x)

    def hex(self):
        return hexlify(bytes(self)).decode()

    def __eq__(self, other):
        if isinstance(other, int):
            return self.x == other
        if not isinstance(other, Mod):
            return False
        return self.x == other.x and self.n == other.n

    def __ne__(self, other):
        return not self == other

    def __pow__(self, n):
        if type(n) is not int:
            raise TypeError

        q = self
        r = self if n & 1 else Mod(1, self.n)

        i = 2
        while i <= n:
            q = q * q
            if n & i == i:
                r = q * r
            i = i << 1
        return r


def add(P: Tuple[Mod, Mod], Q: Tuple[Mod, Mod], a: Mod, b: Mod):
    """
    Add two points `P` and `Q` together, on a short Weierstrass curve
    defined by:  y^2 = x^3 + ax + b.

    Points should be a tuple of `Mod`s, `a` and `b` should be `Mod`s.
    """
    px, py = P
    qx, qy = Q
    if px == 0 and py == 1:
        return Q
    if qx == 0 and qy == 1:
        return P
    if px == qx and py == -qy:
        return 0, 1
    if px == qx and py == qy:
        return dbl(P, a, b)
    lmb = (qy - py) / (qx - px)
    x = lmb * lmb - px - qx
    y = lmb * (px - x) - py
    return x, y


def dbl(P: Tuple[Mod, Mod], a: Mod, b: Mod):
    """
    Double the point `P`, on a short Weierstrass curve
    defined by:  y^2 = x^3 + ax + b.

    Point should be a tuple of `Mod`s, `a` and `b` should be `Mod`s.
    """
    px, py = P
    if px == 0 and py == 1:
        return P
    if py == 0:
        return 0, 1
    lmb = (3 * px * px + a) / (2 * py)
    x = lmb * lmb - 2 * px
    y = lmb * (px - x) - py
    return x, y


def rtl(scalar: int, point: Tuple[Mod, Mod], a: Mod, b: Mod):
    """
    Perform right-to-left double and add scalar multiplication of `point`,
    by `scalar`, on a short Weierstrass curve defined by:
    y^2 = x^3 + ax + b
    """
    if scalar < 0:
        r = rtl(-scalar, point, a, b)
        return r[0], -r[1]
    q = point
    r = (0, 1)
    while scalar > 0:
        if scalar & 1 != 0:
            r = add(r, q, a, b)
        q = dbl(q, a, b)
        scalar >>= 1
    return r


def compress(point: Tuple[Mod, Mod]):
    """Encode curve `point` as 256-bit string"""
    return sha256(bytes(point[0]) + bytes(point[1])).hexdigest()


def ecdh(privkey: int, pubkey: Tuple[Mod, Mod], a: Mod, b: Mod):
    """
    Perform ECDH between `privkey` and `pubkey`, and return the shared secret,
    on a short Weierstrass curve defined by:
    y^2 = x^3 + ax + b
    """
    x, y = pubkey

    shared_point = rtl(privkey, (x, y), a, b)
    secret = compress(shared_point)
    return secret


# IA174Curve
curve = {}
curve["p"] = 0x586BE5268256AE12D62631EFC2784D02DCFF420D262DA9CD94C62D5808BEE24D
curve["a"] = Mod(0x7E7, curve["p"])
curve["b"] = Mod(0x0, curve["p"])
curve["gx"] = Mod(
    0x19905ED22F9466CDF2FFC77877FD5A5519E11143FC9D691DED44ED6809AB4F50, curve["p"]
)
curve["gy"] = Mod(
    0x4AAC2A737CD8D1C15EE3D7C7F1B30F1E685599CB3C117012DF1AA67AC66AE384, curve["p"]
)
curve["n"] = 0x200000000000000000000000000002E1
curve["h"] = 0x2C35F293412B57096B1318F7E13C2286A
