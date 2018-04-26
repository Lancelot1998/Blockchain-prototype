# -*- coding: utf-8 -*-
"""
    conchain
    ~~~~~~~~~~

    Implements blockchain consensus mechanisms

    :author: hank
"""
from source.transfer import MsgType, PeerManager, recv_parser
from source.blockchain import Transaction, Block

from random import randrange, seed
import struct
import hashlib
from queue import Queue
import socketserver
import concurrent.futures
from multiprocessing import Value, Pool, Lock
from functools import partial

MINE_TOP = 2 ** 32
MINE_SWITCH = Value('i', 1)


class PoWServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_address, handler):
        self.prev_hash = b''
        self.target = (2**232 - 1).to_bytes(32, byteorder='big')
        # self.nonce = None
        self.block_cache = Queue()
        self.peer = PeerManager()
        self.workers = Pool()

        # self.switch = Value('i', 0)

        self.lock = Lock()
        self.lock.acquire()

        socketserver.TCPServer.__init__(server_address, handler, bind_and_activate=True)

    def serve_forever(self, poll_interval=0.5):

        self.set_prev_hash()
        self.set_target()
        self.start_miner()

        super().serve_forever()

    def start_miner(self):

        ore = self.workers.apply_async(self.__mine,
                                       args=(self.prev_hash, self.target),
                                       callback=partial(self.on_new_block_mined, self))


    @staticmethod
    def on_new_block_mined(self: 'PoWServer', future: concurrent.futures.Future):
        """
        try to add the block that the server itself mines to the chainbase
        :param self: the instance of PoWServer
        :param future: Future object contains mining result
        :return: None
        """
        prev_hash_, target_, nonce = future.result()


        if prev_hash_ == self.prev_hash and target_ == self.target:  # if conditions confirm, the server wins mining
            if nonce < 0:  # mining stops without result
                return
            block = self.make_block(nonce)
            self.peer.sendall(msgtype=MsgType.TYPE_NEW_BLOCK, content=block.b)
            assert self.add_block(block.b) is True
            self.prev_hash = block.hash
            self.start_miner()

    def on_new_block_received(self, block):
        if self.add_block(block):
            self.prev_hash = block.hash
            self.start_miner()

    def set_prev_hash(self):
        """get previous hash from chainbase when initializing"""
        pass

    def set_target(self):
        pass

    def make_block(self, nonce) -> Block:
        pass

    def add_block(self, block: bytes) -> bool:
        """
        add the block to the chainbase, if return value is OK, update prev_hash
        :param block: binary block
        :return: True | False
        """
        pass

    def acquire_block(self, index):
        pass


    @staticmethod
    def __mine(prev_hash, target):
        """
        find a valid nonce
        :param prev_hash:
        :param target:
        :return: Tuple of (prev_hash, target, nonce)
        """
        seed()
        initial = randrange(0, MINE_TOP)  # [0, 2**32]

        for nonce in range(initial, MINE_TOP):
            if MINE_SWITCH.value == 0:
                MINE_SWITCH.value = 1
                return prev_hash, target, -1
            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

        for nonce in range(0, initial):
            if MINE_SWITCH.value == 0:
                MINE_SWITCH.value = 1
                return prev_hash, target, -1
            hash_ = PoWServer.__calc_hash(prev_hash, nonce)

            if hash_ < target:
                return prev_hash, target, nonce

    @staticmethod
    def __calc_hash(prev_hash, nonce: int) -> bytes:  # calculate SHA256(SHA256(prev_hash+nonce))
        sha = hashlib.sha256()
        sha.update(prev_hash)
        sha.update(struct.pack('=I', nonce))
        hash_ = sha.digest()
        sha = hashlib.sha256()
        sha.update(hash_)
        hash_ = sha.digest()

        return hash_


class PowHandler(socketserver.StreamRequestHandler):
    def handle(self):
        header, length, msgtype, content = recv_parser(self.request)

        if msgtype == MsgType.TYPE_NEW_BLOCK:
            self.server.on_new_block_received(content)

        elif msgtype == MsgType.TYPE_BLOCK_READ:
            self.server.acquire_block(content)

        elif msgtype == MsgType.TYPE_NODE_DISCOVER:
            pass


if __name__ == '__main__':
    import random
    address = ('localhost', 23333)
    print(address)
    with PoWServer(address, PowHandler) as server:
        server.serve_forever()