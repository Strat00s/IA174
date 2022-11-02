"""
The implementation of the KeeLoq cipher. The `encrypt` and `decrypt` functions are taken
directly from the source: https://github.com/socram8888/leekoq
"""

import math
from typing import Final
import typing

from utils import int2bytes, bytes2int, XOR

LUT: Final[int] = 0x3A5C742E

KEELOQ_BYTE_BLOCK_SIZE: Final[int] = 4


def encrypt(block: int, key: int) -> int:
    """
    Encrypts a 32-bit block of plaintext using the KeeLoq algorithm.

    :param int block: 32-bit plaintext block
    :param int key: 64-bit key
    :return: 32-bit ciphertext block
    :rtype: int
    """

    for i in range(528):
        # Calculate LUT key
        lutkey = (block >> 1) & 1 | (block >> 8) & 2 | (block >> 18) & 4 | (block >> 23) & 8 | (block >> 27) & 16

        # Calculate next bit to feed
        msb = (block >> 16 & 1) ^ (block & 1) ^ (LUT >> lutkey & 1) ^ (key & 1)

        # Feed it
        block = msb << 31 | block >> 1

        # Rotate key right
        key = (key & 1) << 63 | key >> 1

    return block


def decrypt(block: int, key: int) -> int:
    """
    Decrypts a 32-bit block of ciphertext using the KeeLoq algorithm.

    :param int block: 32-bit ciphertext block
    :param int key: 64-bit key
    :return: 32-bit plaintext block
    :rtype: int
    """

    for i in range(528):
        # Calculate LUT key
        lutkey = (block >> 0) & 1 | (block >> 7) & 2 | (block >> 17) & 4 | (block >> 22) & 8 | (block >> 26) & 16

        # Calculate next bit to feed
        lsb = (block >> 31) ^ (block >> 15 & 1) ^ (LUT >> lutkey & 1) ^ (key >> 15 & 1)

        # Feed it
        block = (block & 0x7FFFFFFF) << 1 | lsb

        # Rotate key left
        key = (key & 0x7FFFFFFFFFFFFFFF) << 1 | key >> 63

    return block


def KeeLoq_enc(msg: bytes, K: bytes) -> bytes:
    """
    Keeloq encryption (ECB mode) with input and output as bytes - original Keeloq functions (see encrypt, decrypt above) works with integers

    :param msg: plaintext (one block only = 32 bits)
    :param K: 8 bytes = 64 bits
    :return: ciphertext (one block only = 32 bits)
    """
    ctx_int = encrypt(block=bytes2int(msg), key=bytes2int(K))
    return int2bytes(ctx_int)


def KeeLoq_dec(msg: bytes, K: bytes) -> bytes:
    """
    Keeloq decryption (ECB mode) with input and output as bytes - original Keeloq functions (see encrypt, decrypt above) works with integers

    :param msg: ciphertext (one block only = 32 bits)
    :param K: 8 bytes = 64 bits
    :return: plaintext (one block only = 32 bits)
    """
    ptx_int = decrypt(block=bytes2int(msg), key=bytes2int(K))
    return int2bytes(ptx_int)


def PKCS7_padding(msg_len: int, block_size: int) -> bytes:
    """
    helper function to be used in CBC mode to create the padding block - see RFC 5652 for description https://www.rfc-editor.org/rfc/rfc5652#section-6.3

    :param msg_len: length of entire message = number of bytes of msg
    :param block_size: length of block (in bytes) that uses corresponding block cipher (e.g. for AES block_size = 16 )
    :return: padding (block which should be appended to msg)
    """

    padding_size = block_size - (msg_len % block_size)
    padding = [padding_size] * padding_size
    return bytes(padding)


def pad(msg: bytes, block_size: int) -> bytes:
    """
    if msg has complete last block than one extra block is appended = padded message (in case of PKCS7) is always bigger than original msg
    :param msg:
    :param block_size: the block sizes in bytes
    :return: padded message = concatenation of original msg and PKCS7 padding
    """
    padding = PKCS7_padding(msg_len=len(msg), block_size=block_size)
    return msg + padding


def KeeLoq_CBC_enc(msg: bytes, IV: bytes, K: bytes) -> bytes:
    """
    Encrypts the message `msg` using the key `K` and initialization vector `IV` using
    the KeeLoq cipher in the CBC mode.

    :param msg: arbitrary size
    :param IV: block size = 4B
    :param K: key size = 8B
    :return: Keeloq CBC ciphertext
    """
    #pad the message
    padded  = bytes(msg)
    padded += PKCS7_padding(len(msg), KEELOQ_BYTE_BLOCK_SIZE)
    res     = bytes()
    
    #go through every block and encrypt it
    for i in range(0, len(padded) // KEELOQ_BYTE_BLOCK_SIZE):
        pt_block = padded[i * KEELOQ_BYTE_BLOCK_SIZE : (i + 1) * KEELOQ_BYTE_BLOCK_SIZE]
        xored    = XOR(pt_block, IV)
        ct_block = KeeLoq_enc(xored, K)
        IV       = ct_block
        res     += ct_block
    return res

def unpad(msg: bytes) -> bytes:
    """
    last byte represent number of bytes used as padding - use unpad after decryption not before :)
    :param msg: decrypted plaintext with padding
    :return: unpaded msg
    """
    padding_size = msg[-1]
    assert 1 <= padding_size <= 4
    return msg[:-padding_size]


def KeeLoq_CBC_dec(msg: bytes, IV: bytes, K: bytes) -> bytes:
    """
    :param msg: Keelloq CBC ciphertext
    :param IV: 4 bytes
    :param K: 8 bytes
    :return: Keelloq CBC plaintext (with padding)
    """

    msg_padded = msg
    num_blocks = len(msg) // KEELOQ_BYTE_BLOCK_SIZE

    ctx_block_previous = IV
    res = bytes()
    for idx in range(num_blocks):
        ctx_block = msg_padded[idx * KEELOQ_BYTE_BLOCK_SIZE: (idx + 1) * KEELOQ_BYTE_BLOCK_SIZE]
        decrypted_block = KeeLoq_dec(msg=ctx_block, K=K)
        ptx_block = XOR(decrypted_block, ctx_block_previous)
        ctx_block_previous = ctx_block
        res += ptx_block

    res = unpad(res)
    return res


if __name__ == "__main__":

    import secrets

    def test_KeeLoq_CBC(msg_size: int):
        """
        Tests whether randomly generated message encrypted with `KeeLoq_CBC_enc` and
        decrypts using `KeeLoq_CBC_dec` to the original plaintext. The key and initialization
        vector are generated randomly. `AssertionError` is raised in case the test fails.

        :param msg_size: the byte size of the randomly generated message
        """
        msg = secrets.token_bytes(msg_size)
        key = secrets.token_bytes(8)
        iv = secrets.token_bytes(4)

        ctx = KeeLoq_CBC_enc(msg, IV=iv, K=key)
        ptx = KeeLoq_CBC_dec(ctx, IV=iv, K=key)

        assert msg == ptx, "Error: the {msg.hex(sep=' ')} was decrypted to {ptx.hex(' ')}"

    # Execute the test for several lengths of messages
    for msg_size in [0, 1, 15, 32, 128, 1024, 1025]:
        test_KeeLoq_CBC(msg_size)
    # All tests have passed in case that no AssertionError occurs
    print("All tests passed")
