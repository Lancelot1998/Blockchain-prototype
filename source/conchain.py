# -*- coding: utf-8 -*-
"""
    conchain
    ~~~~~~~~~~

    Implements blockchain consensus mechanisms

    :author: hank
"""

from random import randrange, seed
import struct
import hashlib
from queue import Queue
from source.transfer import MsgType
from source.blockchain import Transaction, Block


MINE_TOP = 2 ** 32


class PoW:
    def __init__(self):
        self.prev_hash = b''
        self.target = 2**232 - 1
        self.block_cache = Queue()

    def mine(self) -> int:
        seed()
        initial = randrange(0, MINE_TOP)  # [0, 2**32]

        for nonce in range(initial, MINE_TOP):
            hash_ = self.calc_hash(nonce)

            if hash_ < self.target.to_bytes(32, byteorder='big'):
                return nonce

        for nonce in range(0, initial):
            hash_ = self.calc_hash(nonce)

            if hash_ < self.target.to_bytes(32, byteorder='big'):
                return nonce

    def calc_hash(self, nonce: int) -> bytes:
        sha = hashlib.sha256()
        sha.update(self.prev_hash)
        sha.update(struct.pack('=I', nonce))
        hash_ = sha.digest()
        sha = hashlib.sha256()
        sha.update(hash_)
        hash_ = sha.digest()

        return hash_
