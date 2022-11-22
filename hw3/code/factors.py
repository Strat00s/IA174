p = 0x586be5268256ae12d62631efc2784d02dcff420d262da9cd94c62d5808bee24d
a = 0x7e7
b = 0x0

n1 = 940258296925944608662895221235664431210
n2 = 42535295865117307932921825928971027169

x = n1

print(n1 * n2)
print(f"The factors of {x} are:")
i = 1
while True:
    if x % i == 0:
        x = x // i
        print(i)
    if x == 1:
        break
    i += 1
print(n2)