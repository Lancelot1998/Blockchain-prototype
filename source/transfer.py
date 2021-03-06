from typing import List, Tuple, NewType, Iterator
from source.utility import n_bytes
from source.blockchain import Transaction, BLENGTH_INT
import struct
from functools import reduce
from enum import Enum, unique


PIECE = 4096
LENGTH_HEADER = 64  # 4 len + 4 type + 56 blank(if heartbeat or PBFT, these are content)
LENGTH_TYPE = 4

@unique
class MsgType(Enum):
    TYPE_NORMAL = struct.pack('=i', 0)
    TYPE_HEARTBEAT = struct.pack('=i', 1)
    TYPE_PRE_PREPARE = struct.pack('=i', 2)
    TYPE_PREPARE = struct.pack('=i', 3)
    TYPE_COMMIT = struct.pack('=i', 4)
    TYPE_TRANS = struct.pack('=i', 5)
    TYPE_TRANS_WRITE = struct.pack('=i', 6)
    TYPE_TRANS_RETRIEVE = struct.pack('=i', 7)
    TYPE_BLOCK_WRITE = struct.pack('=i', 8)
    TYPE_RESPONSE_OK = struct.pack('=i', 9)
    TYPE_RESPONSE_ERROR = struct.pack('=i', 10)
    TYPE_TRANS_READ = struct.pack('=i', 11)
    TYPE_TRANS_SEARCH = struct.pack('=i', 12)


def b_block_pack(block: bytes) -> List[bytes]:
    p = len(block) % PIECE
    packages = n_bytes(block[:-p], PIECE)
    packages.append(block[-p:])
    return packages

def batch_handler(batch: List) -> bytes:
    """
    process a list of binary content to a binary string
    :param batch: a list of binary content
    :return: the content can be feed to send_handler()
    """
    length = [struct.pack('=i', len(individual)) for individual in batch]
    return reduce(lambda x, y: x + y, [l + c for l, c in zip(length, batch)])

def batch_parser(batch: bytes) -> List:
    """
    process a received binary string to a list of binary content
    :param batch: received binary string
    :return: a list of binary content
    """
    result = []
    i = 0
    while i < len(batch):
        l = struct.unpack('=i', batch[i:i+BLENGTH_INT])[0]
        i = i + l + BLENGTH_INT
        result.append(batch[i-l:i])
    return result


def send_handler(type: MsgType, content) -> bytes:
    """
    pack content to be sent
    :param type: content type
    :param content: binary content
    :return: packed content can be send directly
    """
    payload =  b''.join((struct.pack('=i', len(content)), type.value,
                         bytes(LENGTH_HEADER - BLENGTH_INT - LENGTH_TYPE), content))
    return payload


def recv_parser(request):
    header = request.recv(LENGTH_HEADER)
    length, msgtype = header_parser(header)
    content = recv_content(length, request)

    return header, length, msgtype, content


def header_parser(header: bytes):
    assert len(header) == LENGTH_HEADER

    length = struct.unpack('=i', header[:4])[0]
    msgtype = MsgType(header[4:8])

    return length, msgtype


def recv_content(length: int, request) -> bytes:
    content = bytes()
    l = 0

    while l < length:
        piece = request.recv(min(PIECE, length - l))
        content += piece
        l += len(piece)

    return content
