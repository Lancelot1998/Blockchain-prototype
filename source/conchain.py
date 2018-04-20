# -*- coding: utf-8 -*-
"""
    conchain
    ~~~~~~~~~~

    Implements blockchain consensus mechanisms

    :author: hank
"""

from random import randrange
import struct
import hashlib
from queue import Queue
from source.transfer import MsgType
from source.blockchain import Transaction, Block


MINE_TOP = 2 ** 32


class PoW:
    def __init__(self):
        self.prev_hash = b''
        self.target = bytes(32)
        self.block_cache = Queue()

    def mine(self) -> int:
        initial = randrange(0, MINE_TOP)  # [0, 2**32]

        for nonce in range(initial, MINE_TOP):
            sha = hashlib.sha256()
            sha.update(self.prev_hash)
            sha.update(struct.pack('=I', nonce))
            hash = sha.digest()

            if hash < self.target:
                return nonce

        for nonce in range(0, initial):
            sha = hashlib.sha256()
            sha.update(self.prev_hash)
            sha.update(struct.pack('=I', nonce))
            hash = sha.digest()

            if hash < self.target:
                return nonce