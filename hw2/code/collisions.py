from typing import Tuple
import secrets
from macs import MAC_KeeLoq, SHA1
from utils import XOR
from keeloq import KEELOQ_BYTE_BLOCK_SIZE
"""uncoment commented sections for multiprocessing and comment out 'MAC_combined_collision' and lines 133 - 159"""
#from multiprocessing import Pool
#from functools import reduce


BLOCK_SIZE = KEELOQ_BYTE_BLOCK_SIZE

def MAC_Keeloq_collision(K: bytes, MAC_size: int) -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `MAC_KeeLoq` function.

    :param K: the K for the underlying KeeLoq cipher
    :param MAC_size: the size in bytes of the final MAC
    :return: a tuple of two disctinct messages that have the same KeeLoq CBC-MAC
    """
    ms_len = BLOCK_SIZE * 2 #message length of at least 2 blocks
    if MAC_size > ms_len:
        ms_len += BLOCK_SIZE * (MAC_size // BLOCK_SIZE - 2)

    m1 = secrets.token_bytes(ms_len)                                        #generate variable size message depending on mac size (but at least 2 blocks)
    state = MAC_KeeLoq(m1[:BLOCK_SIZE], K, BLOCK_SIZE * 2)[:BLOCK_SIZE]     #get the first inner state (second one contains padding)
    m2   = XOR(state, m1[BLOCK_SIZE:BLOCK_SIZE * 2]) + m1[BLOCK_SIZE * 2:]  #forge second message
    return (m1, m2)


def SHA1_collision() -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `SHA1` function.

    :return: a tuple of two distinct messages that have the same SHA1 hash
    """
    prefix = bytearray.fromhex("255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe01")
    m1_1   = bytearray.fromhex("7f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c2")
    m1_2   = bytearray.fromhex("30570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1")
    m2_1   = bytearray.fromhex("7346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d2")
    m2_2   = bytearray.fromhex("3c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1")
    
    m1 = prefix + m1_1 + m1_2
    m2 = prefix + m2_1 + m2_2
    
    apnd_len = secrets.randbelow(80)
    something = secrets.token_bytes(apnd_len)
    
    m1 += something
    m2 += something

    return (m1, m2)


def MAC_combined_collision(Keeloq_MAC_size: int=4) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Generate a quadruple (msg1, key1, msg2, key2) that forms a collision under the `MAC_combined`
    function. That means that for the aformentioned quadruple it holds that msg1 != msg2 and:

				SHA1(msg1 | MAC_KeeLoq(msg1, key1)) == SHA1(msg2 | MAC_KeeLoq(msg2, key2))

    :return: a quadruple (msg1, key1, msg2, key2)
    """
    m1, m2 = SHA1_collision()
    macs1 = dict()
    macs2 = dict()
    while(True):
        key = secrets.token_bytes(8)
        mac1 = MAC_KeeLoq(m1, key, Keeloq_MAC_size)
        mac2 = MAC_KeeLoq(m2, key, Keeloq_MAC_size)
        macs1[mac1] = key
        macs2[mac2] = key
        if mac1 in macs2:
            k1 = key
            k2 = macs2[mac1]
            break
        if mac2 in macs1:
            k2 = key
            k1 = macs1[mac2]
            break

    return (m1, k1, m2, k2)

#def multiprocessing_func(data):
#    keys = data[0]
#    m1 = data[1]
#    m2 = data[2]
#    mac_size = data[3]
#    result = list()
#    for key in keys:
#        mac1 = MAC_KeeLoq(m1, key, mac_size)
#        mac2 = MAC_KeeLoq(m2, key, mac_size)
#        result.append((mac1, mac2, key))
#    return result
#
#def MAC_combined_collision(Keeloq_MAC_size: int=4) -> Tuple[bytes, bytes, bytes, bytes]:
#    NPROC = 12 #Numer of available processors
#    pool = Pool(NPROC)
#    
#    ms_dict = dict()
#    step = 0
#    mac1_dict = dict()
#    mac2_dict = dict()
#
#    m1, m2 = SHA1_collision()
#
#    while True:
#        step += 1000
#        results = pool.map(multiprocessing_func, [[[secrets.token_bytes(8) for j in range(step)], m1, m2, Keeloq_MAC_size] for i in range(NPROC + 1)])
#        results = reduce(lambda x, y: x + y, results)
#
#        for mac1, mac2, key in results:
#            if mac1 in mac2_dict:
#                k1 = key
#                k2 = mac2_dict[mac1]
#                break
#            else:
#                mac1_dict[mac1] = key
#            if mac2 in mac1_dict:
#                k2 = key
#                k1 = mac1_dict[mac2]
#                break
#            else:
#                mac2_dict[mac2] = key
#        else:
#            print(f"{len(mac1_dict)} {len(mac2_dict)}")     #"progress"
#            continue
#        break
#
#    return (m1, k1, m2, k2)


key      = b'\01\23\45\67\89\ab\cd\ef'
mac_size = 80
messages = MAC_Keeloq_collision(key, mac_size)
print("Task 2a:")
print(f"m1: {messages[0].hex()}")
print(f"m2: {messages[1].hex()}")
print(f"MAC1: {MAC_KeeLoq(messages[0], key, mac_size).hex()}")
print(f"MAC2: {MAC_KeeLoq(messages[1], key, mac_size).hex()}")
print("-----------------------------------------")

messages = SHA1_collision()
print("Task 2b:")
print(f"m1: {messages[0].hex()}")
print(f"m2: {messages[1].hex()}")
print(f"SHA11: {SHA1(messages[0]).hex()}")
print(f"SHA12: {SHA1(messages[1]).hex()}")
print("-----------------------------------------")

mac_size = 4
pairs = MAC_combined_collision(mac_size)
print("Task 2c:")
print(f"m1: {pairs[0].hex()}")
print(f"k1: {pairs[1].hex()}")
print(f"m2: {pairs[2].hex()}")
print(f"k2: {pairs[3].hex()}")
print(f"SHA11: {SHA1(MAC_KeeLoq(pairs[0], pairs[1], mac_size)).hex()}")
print(f"SHA12: {SHA1(MAC_KeeLoq(pairs[2], pairs[3], mac_size)).hex()}")

#if __name__=='__main__':
#    key      = b'\01\23\45\67\89\ab\cd\ef'
#    mac_size = 80
#    messages = MAC_Keeloq_collision(key, mac_size)
#    print("Task 2a:")
#    print(f"m1: {messages[0].hex()}")
#    print(f"m2: {messages[1].hex()}")
#    print(f"MAC1: {MAC_KeeLoq(messages[0], key, mac_size).hex()}")
#    print(f"MAC2: {MAC_KeeLoq(messages[1], key, mac_size).hex()}")
#    print("-----------------------------------------")
#
#    messages = SHA1_collision()
#    print("Task 2b:")
#    print(f"m1: {messages[0].hex()}")
#    print(f"m2: {messages[1].hex()}")
#    print(f"SHA11: {SHA1(messages[0]).hex()}")
#    print(f"SHA12: {SHA1(messages[1]).hex()}")
#    print("-----------------------------------------")
#
#    mac_size = 4
#    pairs = MAC_combined_collision(mac_size)
#    print("Task 2c:")
#    print(f"m1: {pairs[0].hex()}")
#    print(f"k1: {pairs[1].hex()}")
#    print(f"m2: {pairs[2].hex()}")
#    print(f"k2: {pairs[3].hex()}")
#    print(f"MAC1: {MAC_KeeLoq(pairs[0], pairs[1], mac_size).hex()}")
#    print(f"MAC2: {MAC_KeeLoq(pairs[2], pairs[3], mac_size).hex()}")
#    print(f"SHA11: {SHA1(MAC_KeeLoq(pairs[0], pairs[1], mac_size)).hex()}")
#    print(f"SHA12: {SHA1(MAC_KeeLoq(pairs[2], pairs[3], mac_size)).hex()}")
