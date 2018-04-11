import os
from socketserver import BaseRequestHandler
import time
from typing import List, Tuple, NewType
from source.transfer import *
from source.blockchain import Blockchain, Block, Attachment, BlockData, Transaction
import socket
import logging
from multiprocessing import Pool
from enum import Enum, unique
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac



if hasattr(os, "fork"):
    from socketserver import ForkingTCPServer as TCPServer
    from multiprocessing import Lock
else:
    from socketserver import ThreadingTCPServer as TCPServer
    from threading import Lock


@unique
class StatePBFT(Enum):
    IDLE = 0
    PRE_PREPARE = 1
    PREPARE = 2
    COMMIT = 3
    REPLY = 4


class BlockchainMixin:
    content = set()
    lock = Lock()
    trans = []
    chain = Blockchain()
    state = StatePBFT.IDLE
    __secrets = b'Look onmyworksyemightyanddespair'
    master_node = -1
    n_request = 0
    temp_block = []

    def is_master(self):
        return self.index == self.master_node

    @classmethod
    def set_connection(cls, connection: List[Tuple[str, int]]) -> None:
        cls.connection = connection

    @classmethod
    def set_pool(cls, pool) -> None:
        cls.pool = pool

    @classmethod
    def set_view(cls, view: int) -> None:
        cls.view = view

    @classmethod
    def set_nodes(cls, n_nodes: int) -> None:
        cls. num_nodes = n_nodes

    @classmethod
    def set_index(cls, index: int) -> None:
        cls.index = index

    @classmethod
    def set_ntrans(cls, num_trans_per_block: int) -> None:
        cls.trans_limit = num_trans_per_block

    @staticmethod
    def pre_prepare_msg(view: int, n_request: int, content: bytes) -> bytes:
        h = hmac.HMAC(BlockchainMixin.__secrets, hashes.SHA256(), backend=default_backend())
        h.update(content)
        msg = b''.join([struct.pack('=i', len(content)),
                        TYPE_PRE_PREPARE,
                        struct.pack('=2i', view, n_request),
                        bytes(16), h.finalize(), content])
        return msg

    @staticmethod
    def prepare_msg(view: int, n_request: int, index: int, content: bytes) -> bytes:
        h = hmac.HMAC(BlockchainMixin.__secrets, hashes.SHA256(), backend=default_backend())
        h.update(content)
        msg = b''.join([struct.pack('=i', len('')),
                        TYPE_PREPARE,
                        struct.pack('=2i', view, n_request), struct.pack('=i', index),
                        bytes(12), h.finalize()])
        return msg

    @staticmethod
    def commit_msg(view: int, n_request: int, index: int, content: bytes) -> bytes:
        h = hmac.HMAC(BlockchainMixin.__secrets, hashes.SHA256(), backend=default_backend())
        h.update(content)
        msg = b''.join([struct.pack('=i', len('')),
                        TYPE_COMMIT,
                        struct.pack('=2i', view, n_request), struct.pack('=i', index),
                        bytes(12), h.finalize()])
        return msg




class BlockchainServer(TCPServer, BlockchainMixin):
    pass


class BlockchainHandler(BaseRequestHandler):
    # handler_log = logging.getLogger('handler_log')
    # fhandler_log = logging.FileHandler('../log/BlockchainHandler_pid{0}.txt'.format(os.getpid()), 'w')
    # handler_log.addHandler(fhandler_log)
    # handler_log.setLevel(logging.DEBUG)

    @staticmethod
    def sends(address, contents):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # self.handler_log.debug((ip, port))
            # print(address)
            time.sleep(len(contents) / (0.01 * 1024 ** 3))
            sock.connect(address)
            sock.sendall(contents)

    def handle(self):
        flag = 0
        # print(BlockchainMixin.state)
        while True:
            header = self.request.recv(LENGTH_HEADER)

            if len(header) == 0:
                # self.handler_log.debug('pid {0} Round end: {1}'.format(os.getpid(), time.time()))
                # print('pid {0} Round end: {1}'.format(os.getpid(), time.time()))
                break

            if flag == 0:
                # self.handler_log.debug('pid {0} Round start: {1}'.format(os.getpid(), time.time()))
                # print('pid {0} Round start: {1}'.format(os.getpid(), time.time()))
                flag = 1

            typ = header[4:8]
            len_h = struct.unpack('=i', header[:4])[0]
            content = bytes()

            '''Just receive all the content'''
            l = 0
            while l < len_h:
                piece = self.request.recv(min(PIECE, len_h - l))
                content += piece
                l += len(piece)

            '''Check whether the block content has been received (hash or keyword IN)
            if so, continue the loop'''
            # print('received from: ', self.request.getpeername())

            '''PBFT state machine'''
            if BlockchainMixin.state is StatePBFT.IDLE:
                if typ == TYPE_TRANS:  # keep receiving trans until reach the limitation
                    BlockchainMixin.lock.acquire()
                    BlockchainMixin.trans.append(Transaction.unpack(content))
                    BlockchainMixin.lock.release()
                    if len(BlockchainMixin.trans) == BlockchainMixin.trans_limit:  # prepare a block
                        at = Attachment()
                        at.add_data(b'')
                        at.ready()

                        bd = BlockData(BlockchainMixin.trans, at)
                        block = Block(BlockchainMixin.chain.chain[-1].index + 1, time.time(), bd, BlockchainMixin.chain.chain[-1].hash)
                        msg = BlockchainMixin.pre_prepare_msg(BlockchainMixin.view, BlockchainMixin.n_request, block.b)


                        BlockchainMixin.n_request += 1
                        BlockchainMixin.state = StatePBFT.PREPARE
                        BlockchainMixin.temp_block.append(block.b)
                        for ip, port in BlockchainMixin.connection:
                            if (ip, port) == self.request.getpeername():
                                continue
                            BlockchainMixin.pool.apply_async(self.sends, ((ip, port), msg))

                        BlockchainMixin.trans.clear()



                elif typ == TYPE_PRE_PREPARE:  # cache the block and response with PREPARE message
                    BlockchainMixin.lock.acquire()
                    # print('content', content)
                    BlockchainMixin.temp_block.append(content)
                    BlockchainMixin.state = StatePBFT.PREPARE
                    BlockchainMixin.lock.release()
                    msg = BlockchainMixin.prepare_msg(BlockchainMixin.view, BlockchainMixin.num_nodes, BlockchainMixin.index, content)
                    for ip, port in BlockchainMixin.connection:
                        BlockchainMixin.pool.apply_async(self.sends, ((ip, port), msg))

            elif BlockchainMixin.state is StatePBFT.PREPARE:
                if typ == TYPE_PREPARE or typ == TYPE_COMMIT:
                    BlockchainMixin.lock.acquire()
                    BlockchainMixin.state = StatePBFT.COMMIT
                    BlockchainMixin.lock.release()
                    msg = BlockchainMixin.commit_msg(BlockchainMixin.view, BlockchainMixin.num_nodes, BlockchainMixin.index, content)
                    for ip, port in BlockchainMixin.connection:
                        BlockchainMixin.pool.apply_async(self.sends, ((ip, port), msg))

            elif BlockchainMixin.state is StatePBFT.COMMIT:
                if typ == TYPE_COMMIT:
                    BlockchainMixin.lock.acquire()
                    BlockchainMixin.state = StatePBFT.REPLY
                    BlockchainMixin.chain.add_block(Block.unpack(BlockchainMixin.temp_block[0]))
                    BlockchainMixin.temp_block.clear()
                    BlockchainMixin.lock.release()
                    msg = BlockchainMixin.commit_msg(BlockchainMixin.view, BlockchainMixin.num_nodes,
                                                     BlockchainMixin.index, content)
                    for ip, port in BlockchainMixin.connection:
                        BlockchainMixin.pool.apply_async(self.sends, ((ip, port), msg))

                    mm = '%f' % time.time()
                    print(mm)
                    with open('logs/srv' + str(BlockchainMixin.index) + '.txt', 'w') as logfile:
                        logfile.writelines([mm])

            elif BlockchainMixin.state is StatePBFT.REPLY:
                pass
                # if typ == TYPE_COMMIT:
                #     BlockchainMixin.state = StatePBFT.IDLE
            # if typ == TYPE_NORMAL:
            #     self.lock.acquire()
            #     if content not in self.content:
            #         # self.handler_log.debug('content not exists')
            #         print('content not exists')
            #         self.content.add(content)
            #     else:
            #         # self.handler_log.debug('content already exists')
            #         print('content already exists')
            #         self.lock.release()
            #         continue
            #     self.lock.release()
            #
            # '''Do the corresponding logic'''
            # if typ == TYPE_NORMAL:
            #
            #     # bc.add_block(Block.unpack(content))
            #     # send header + content to other nodes except peername
            #
            #     for ip, port in self.connection:
            #         if (ip, port) == self.request.getpeername():
            #             continue
            #         self.pool.apply_async(self.sends, ((ip, port), header + content))
            #
            #     self.lock.acquire()
            #     self.chain.add_block(Block.unpack(content))
            #     self.lock.release()
            #
            # elif typ == TYPE_HEARTBEAT:
            #     pass
            #     # print('round end:', time.time())


def start_server(address: Tuple[str, int], connection: List[Tuple[str, int]], index: int, nodes: int):
    BlockchainMixin.set_connection(connection)
    BlockchainMixin.set_pool(Pool())
    BlockchainMixin.set_view(0)
    BlockchainMixin.set_nodes(nodes)
    BlockchainMixin.set_index(index)
    BlockchainMixin.set_ntrans(50000)
    with BlockchainServer(address, BlockchainHandler) as server:
        server.serve_forever()


# if __name__ == "__main__":
#     args =
