from typing import Tuple
import secrets
from macs import MAC_KeeLoq
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
    pass


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
