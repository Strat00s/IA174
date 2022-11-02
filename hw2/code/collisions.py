from typing import Tuple
import secrets
from macs import MAC_KeeLoq, SHA1
from utils import XOR
#from keeloq import KeeLoq_CBC_enc

def MAC_Keeloq_collision(K: bytes, MAC_size: int) -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `MAC_KeeLoq` function.

    :param K: the K for the underlying KeeLoq cipher
    :param MAC_size: the size in bytes of the final MAC
    :return: a tuple of two disctinct messages that have the same KeeLoq CBC-MAC
    """
    text  = "12340f0f" + "0f0f" * (MAC_size // 4 - 2)   #generate variable size message depending on mac size
    ms1   = bytes(text, "utf-8")
    state = MAC_KeeLoq(ms1[:4], K, 8)[:4]   #get the first inner state (second one contains padding)
    ms2   = XOR(state, ms1[4:8]) + ms1[8:]  #forge second message
    return (ms1, ms2)


def SHA1_collision() -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `SHA1` function.

    :return: a tuple of two distinct messages that have the same SHA1 hash
    """
    # TODO: Task 2b finish the implementation
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
    # TODO: Task 2c finish the implementation
    pass

key      = b'\01\23\45\67\89\ab\cd\ef'
mac_size = 24
messages = MAC_Keeloq_collision(key, mac_size)
print(f"m1: {messages[0].hex()}")
print(f"m2: {messages[1].hex()}")
print(f"MAC1: {MAC_KeeLoq(messages[0], key, mac_size).hex()}")
print(f"MAC2: {MAC_KeeLoq(messages[1], key, mac_size).hex()}")


print(f"m1: {messages[0].hex()}")
print(f"m2: {messages[1].hex()}")
print(f"SHA11: {SHA1(messages[0]).hex()}")
print(f"SHA12: {SHA1(messages[1]).hex()}")
