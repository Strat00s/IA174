p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

pub_x = 0x1a9112ae9ac6b30cb8f899f9ed76b4c3826b758d5c98a840afd9eee17d09fe73
pub_y = 0x39525bafcf33493141fd3f57d170f69af4ce41cd76ddb0f418781db2b4da5a8c


ecurve    = EllipticCurve(GF(p), [a, b])
generator = ecurve.gens()[0]
pubkey    = ecurve.point((pub_x, pub_y))
order     = ecurve.order()
factors   = [x*y for (x, y) in order.factor()[:-2]]

print(ecurve)
print(generator)
print(pubkey)
print(order)
print(factors)

residues = []
for factor in factors:
    a =  generator * (order // factor)
    b =  pubkey * (order // factor)
    i = discrete_log(b, a, a.order(), operation='+')
    residues.append(i)

n = crt(residues, factors)
print(n)
modulus = prod(factors)
print(modulus)

while True:
    if generator * n == pubkey:
        print(n)
        break
    n += modulus
