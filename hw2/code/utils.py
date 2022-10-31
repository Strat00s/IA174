def XOR(array1: bytes, array2: bytes) -> bytes:
    """
    Helper function that performs byte-by-byte XOR on the inputs.
    The returned bytestream has the length of the shorter input.

    :param array1:
    :param array2:
    :return: XOR of the two byte arrays
    """
    return bytes([a ^ b for a, b in zip(array1, array2)])


def bytes2int(array: bytes) -> int:
    return int.from_bytes(array, byteorder='big', signed=False)


def int2bytes(integer: int) -> bytes:
    return integer.to_bytes(byteorder='big', length=4, signed=False)
