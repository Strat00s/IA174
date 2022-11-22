from math import sqrt

p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

n1 = 940258296925944608662895221235664431210
n2 = 42535295865117307932921825928971027169

#y*y = x*x*x + a*x + b

#find int x while increasing y

point_cnt = 10
x = 1
while point_cnt:
    y = sqrt((x*x*x + a*x + b) % (n1 * n2))
    if y.is_integer():
        print(f"x: {x}")
        print(f"y: {int(y)}")
        print("-------------")
        point_cnt -= 1
    x += 1