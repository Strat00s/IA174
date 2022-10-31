from typing import Tuple
import secrets

def MAC_Keeloq_collision(K: bytes, MAC_size: int) -> Tuple[bytes, bytes]:
    """
    Generates a pair of messages that forms a collision under the `MAC_KeeLoq` function.

    :param K: the K for the underlying KeeLoq cipher
    :param MAC_size: the size in bytes of the final MAC
    :return: a tuple of two disctinct messages that have the same KeeLoq CBC-MAC
    """
    # TODO: Task 2a finish the implementation
    pass


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
