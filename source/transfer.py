from typing import List, Tuple, NewType, Iterator
from source.utility import n_bytes
import struct

PIECE = 4096
LENGTH_HEADER = 64  # 4 len + 4 type + 56 blank(if heartbeat or PBFT, these are content)
TYPE_NORMAL = struct.pack('=i', 0)
TYPE_HEARTBEAT = struct.pack('=i', 1)
TYPE_PRE_PREPARE = struct.pack('=i', 2)
TYPE_PREPARE = struct.pack('=i', 3)
TYPE_COMMIT = struct.pack('=i', 4)
TYPE_TRANS = struct.pack('=i', 5)


def b_block_pack(block: bytes) -> List[bytes]:
    p = len(block) % PIECE
    packages = n_bytes(block[:-p], PIECE)
    packages.append(block[-p:])
    return packages

