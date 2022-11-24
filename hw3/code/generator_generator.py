p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

print("start")

ecurve    = EllipticCurve(GF(p), [a, b])
order     = ecurve.order()
factors   = [x*y for (x, y) in order.factor()]

print(ecurve)
print(order)
print(factors)

rng_point = ecurve.random_point()

print(rng_point)

while True:
    for factor in factors:
        beta = rng_point * (p / factor)
        if beta == ecurve.point((0, 1)):
            break
    else:
        print(rng_point)
        break
