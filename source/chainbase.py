# -*- coding: utf-8 -*-
"""
    chainbase
    ~~~~~~~~~

    Implements backend of blockchain

    :author: hank
"""

from source.blockchain import Blockchain, Block, TransPool
from source.transfer import MsgType, recv_parser, send_handler, batch_handler
from source.errors import *
from source.utility import bin2int

import socketserver
import struct


class ChainMsgHandler(socketserver.StreamRequestHandler):

    def handle(self):
        """
        handle messages from webchain and conchain
        :return: None
        """

        handlers = {
            # write the submitted transaction to the transpool
            MsgType.TYPE_TRANS_WRITE: self.processor_trans_write,

            # provide transactions in the transpool
            MsgType.TYPE_TRANS_READ: self.processor_trans_read,

            # write the submitted block (the result of consensus) to the blockchain
            MsgType.TYPE_BLOCK_WRITE: self.processor_block_write,

            # search the transaction that has the given txid
            MsgType.TYPE_TRANS_SEARCH_TXID: self.processor_trans_search_txid,

            # return the previous hash for constructing nonce
            MsgType.TYPE_BLOCK_PREVIOUS_HASH: self.processor_prev_hash,

            # send back blocks whose indexes locate in [start, end]
            MsgType.TYPE_BLOCK_READ: self.processor_block_read
        }

        *_, msgtype, content = recv_parser(self.request)

        handlers[msgtype](content)


    def processor_trans_write(self, content):
        result = self.server.transpool.add(content)
        if result:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_trans_read(self, content):
        result = self.server.transpool.read_serialized()
        if len(result) > 0:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')

        self.request.sendall(_)

    def processor_block_write(self, content):
        try:
            block = Block.unpack(content)
        except Exception:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'block unpack error')
        else:
            result = self.server.blockchain.add_block(block)
            if result:
                self.server.transpool.remove(block)
                _ = send_handler(MsgType.TYPE_RESPONSE_OK, b'')
            else:
                _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
        finally:
            self.request.sendall(_)

    def processor_trans_search_txid(self, content):
        try:
            trans = self.server.blockchain.search_transaction(content)
        except TransNotInChain:
            _ = send_handler(MsgType.TYPE_RESPONSE_ERROR, b'')
        else:
            _ = send_handler(MsgType.TYPE_RESPONSE_OK, trans.b)
        finally:
            self.request.sendall(_)

    def processor_prev_hash(self, content):
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, self.server.blockchain.chain.queue[-1].hash))

    def processor_block_read(self, content):
        start = bin2int(content[:4])
        end = bin2int(content[4:8])
        # do the search
        result = []
        for i in range(start, end):
            result.append(self.server.blockchain.chain.queue[i].b)
        # send back result
        self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result)))


class ChainBaseServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """
    Server class to provide chain service
    """
    blockchain = Blockchain()
    transpool = TransPool(blockchain)


if __name__ == '__main__':
    import random
    address = (r'/tmp/chainbase'+str(random.random()))
    print(address)
    with ChainBaseServer(address, ChainMsgHandler) as server:
        server.serve_forever()
