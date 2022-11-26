import requests
from hashlib import sha256
from sage.all import *

def APICall(difficulty: str, endpoint: str, uco:str, data: dict | None = None):
    url = f"https://ia174.fi.muni.cz/hw03/{difficulty}/{endpoint}/{uco}/"
    if data == None:
        request = requests.get(url)
    else:
        request = requests.post(url, json=data)
    
    if request.status_code != 200:
        print(f"Err {request.status_code}: {request.reason}")
        return None

    return  request.json()

def isGenerator(point, curve):
    factors = [x*y for (x, y) in curve.order().factor()]
    for factor in factors:
        if point * factor == curve.point((0, 1, 0)):
            return False
    if point * curve.order() == curve.point((0, 1, 0)):
        return True
    return False

n1 = 940258296925944608662895221235664431210
n2 = 42535295865117307932921825928971027169

p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

pub_x = 0x1a9112ae9ac6b30cb8f899f9ed76b4c3826b758d5c98a840afd9eee17d09fe73
pub_y = 0x39525bafcf33493141fd3f57d170f69af4ce41cd76ddb0f418781db2b4da5a8c

gen_x = 0x19905ED22F9466CDF2FFC77877FD5A5519E11143FC9D691DED44ED6809AB4F50
gen_y = 0x4AAC2A737CD8D1C15EE3D7C7F1B30F1E685599CB3C117012DF1AA67AC66AE384

ecurve  = EllipticCurve(GF(p), [a, b])
order   = ecurve.order()
factors = [x**y for (x, y) in order.factor()][:-1]  #don't use n2, as it is too large

print(f"Curve: {ecurve}")
print(f"  Order:   {order}")
print(f"  Factors: {factors}")

remainders = list()
for factor in factors:
    so_point = ecurve.point((0, 1, 0))
    while so_point.order() != factor:
        rng_point = ecurve.random_point()
        so_point = rng_point * (order // factor)

    print(f"\nSmall order point: {so_point}")
    print(f"  Factor: {factor}")
    print(f"  Order:  {order}")

    data = {"x": f"{hex(int(so_point[0]))}", "y": f"{hex(int(so_point[1]))}"}
    response = APICall("easy", "ecdh", "492875", data)
    if response == None:
        exit()

    secret = response["secret"]
    original_so_point = so_point
    i = 0
    for i in range(0, factor):
        x = int(so_point[0]).to_bytes(length=(p.bit_length() + 7) // 8, byteorder="big")
        y = int(so_point[1]).to_bytes(length=(p.bit_length() + 7) // 8, byteorder="big")
        if sha256(x + y).hexdigest() == secret:
            break
        so_point += original_so_point   #iterate over point until secret match or infinity
    remainders.append((i + 1) % factor)

print(f"Remainders: {remainders}")

generator   = ecurve.point((gen_x, gen_y))
pubkey      = ecurve.point((pub_x, pub_y))
key = crt(remainders, factors)

while generator * key != pubkey:
    key += prod(factors)

print(f"Key: {key}")
