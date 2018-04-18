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


class ChainMsgHandler(socketserver.StreamRequestHandler):

    def handle(self):
        """
        handle messages from webchain and conchain
        :return: None
        """
        header, length, msgtype, content = recv_parser(self.request)

        if msgtype == MsgType.TYPE_TRANS_WRITE:  # write the submitted transaction to the transpool
            result = self.server.transpool.add(content)
            if result:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, b''))
            else:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_ERROR, b''))

        # elif msgtype == MsgType.TYPE_TRANS_RETRIEVE:  # provide transactions in the transpool (for consensus)
        #     self.request.sendall(
        #         send_handler(MsgType.TYPE_RESPONSE_OK,
        #                      batch_handler(self.server.transpool.retrieve_serialized(bin2int(content))))
        #     )

        elif msgtype == MsgType.TYPE_TRANS_READ:  # provide transactions in the transpool
            result = self.server.transpool.read_serialized()
            if len(result) > 0:
                self.request.sendall(
                    send_handler(MsgType.TYPE_RESPONSE_OK, batch_handler(result))
                )
            else:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_ERROR, b''))

        elif msgtype == MsgType.TYPE_BLOCK_WRITE:
            # write the submitted block (the result of consensus) to the blockchain
            try:
                block = Block.unpack(content)
            except Exception:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_ERROR, b''))
            else:
                result = self.server.blockchain.add_block(block)
                if result:
                    self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, b''))
                else:
                    self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_ERROR, b''))

        elif msgtype == MsgType.TYPE_TRANS_SEARCH_TXID:
            try:
                trans = self.server.blockchain.search_transaction(content)
            except TransNotInChain:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_ERROR, b''))
            else:
                self.request.sendall(send_handler(MsgType.TYPE_RESPONSE_OK, trans.b))


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
