from sage.all import *


def isGenerator(point, curve):
    factors = [x**y for (x, y) in curve.order().factor()]
    #multiplying by factors cannot create neutral element
    for factor in factors:
        if point * factor == curve.point((0, 1, 0)):
            return False
    #multiplying by curve order must create neutral element
    if point * curve.order() == curve.point((0, 1, 0)):
        return True
    return False


n1 = 940258296925944608662895221235664431210
n2 = 42535295865117307932921825928971027169

p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

ecurve  = EllipticCurve(GF(p), [a, b])
print(f"Curve:   {ecurve}")
print(f"Order:   {ecurve.order()}")
print(f"Factors: {ecurve.order().factor()}")

generator = ecurve.point((0, 1, 0))
while not isGenerator(generator, ecurve):
    generator = ecurve.random_point()

print(f"\nGenerator: {generator}")
