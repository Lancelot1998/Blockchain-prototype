from typing import List, Tuple, NewType, Iterator
import struct


def n_bytes(b: bytes, n: int) -> List[bytes]:
    return list(map(bytes, list(zip(*[iter(b)] * n))))


def bin2int(bin: bytes) -> int:
    return struct.unpack('=i', bin)[0]