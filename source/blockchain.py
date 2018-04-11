import hashlib
import time
import struct
import os
from typing import List, Tuple, NewType
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_der_public_key, load_der_private_key
from cryptography.hazmat.backends import default_backend
from source.utility import n_bytes
from source.transfer import *
from source.errors import *
from cryptography.hazmat.primitives import hashes, hmac
from enum import Enum, unique



if hasattr(os, "fork"):
    from socketserver import ForkingTCPServer as TCPServer
    from multiprocessing import Lock
else:
    from socketserver import ThreadingTCPServer as TCPServer
    from threading import Lock


CPU = NewType('CPU', int)
RAM = NewType('RAM', int)
BANDWIDTH = NewType('BANDWIDTH', int)
PUBLIC_KEY_HASH = NewType('PUBLIC_KEY_HASH', bytes)
TXID = NewType('TXID', bytes)
OUTPUT_INDEX = NewType('OUTPUT_INDEX', int)
SIGNATURE = NewType('SIGNATURE', bytes)

BLENGTH_PUBLIC_KEY_HASH = 32
BLENGTH_INT = 4
BLENGTH_TXID = 32
BLENGTH_DOUBLE = 8
BLENGTH_BLOCKHASH = 32




class TransInput:

    def __init__(self, trans_input: List[Tuple[TXID, OUTPUT_INDEX]], public_key_hash: PUBLIC_KEY_HASH) -> None:
        self.content = trans_input
        self.public_key_hash = public_key_hash
        self.b = self.__tobin()

    def __getitem__(self, item) -> Tuple[TXID, OUTPUT_INDEX]:
        return self.content[item]

    def __tobin(self) -> bytes:
        b = bytes()
        for ipt in self.content:
            b += ipt[0] + struct.pack('=i', ipt[1])
        b += self.public_key_hash
        return b

    @classmethod
    def unpack(cls, b: bytes) -> 'TransInput':
        Verify.trans_input_checker(b)
        public_key_hash = b[-BLENGTH_PUBLIC_KEY_HASH:]
        b_content = n_bytes(b[:-BLENGTH_PUBLIC_KEY_HASH], BLENGTH_TXID + BLENGTH_INT)
        content = list(map(lambda i: (i[:BLENGTH_TXID], struct.unpack('=i', i[-BLENGTH_INT:])[0]), b_content))
        return cls(content, public_key_hash)


class TransOutput:

    def __init__(self, trans_output: List[Tuple[CPU, RAM, BANDWIDTH, PUBLIC_KEY_HASH]]) -> None:
        self.content = trans_output
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        b = bytes()
        for opt in self.content:
            b += struct.pack('=3i', opt[0], opt[1], opt[2]) + opt[3]
        return b

    def __getitem__(self, item) -> Tuple[CPU, RAM, BANDWIDTH, PUBLIC_KEY_HASH]:
        return self.content[item]

    @classmethod
    def unpack(cls, b: bytes) -> 'TransOutput':
        Verify.trans_output_checker(b)
        b_content = n_bytes(b, BLENGTH_INT * 3 + BLENGTH_PUBLIC_KEY_HASH)
        content = list(
            map(lambda i: tuple((*list(struct.unpack('=3i', i[:3 * BLENGTH_INT])), i[-BLENGTH_PUBLIC_KEY_HASH:])),
                b_content)
        )
        return cls(content)


class Transaction:

    def __init__(self, ipt: TransInput, opt: TransOutput, version: int = 1) -> None:
        self.public_key = None
        self.signature = None
        self.version = version
        self.timestamp = None
        self.txid = None
        self.b = bytes()
        self.ipt = ipt
        self.opt = opt
        self.length = None
        # self.public_key = public_key
        # self.timestamp = time.time()
        # self.signature = Transaction.__sign(struct.pack('f', self.timestamp) + self.ipt.b + self.opt.b, private_key)
        # self.txid, content = self.__hash_trans()
        # self.b = self.__tobin(content)

    @staticmethod
    def __sign(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> SIGNATURE:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def ready(self, private_key: ec.EllipticCurvePrivateKey):
        self.public_key = private_key.public_key()
        self.timestamp = time.time()
        self.signature = Transaction.__sign(struct.pack('=f', self.timestamp) + self.ipt.b + self.opt.b, private_key)
        self.txid, content = self.__hash_trans()
        self.b = self.__tobin(content)
        self.length = len(self.b)

    def __tobin(self, content: bytes) -> bytes:
        return self.txid + content

    def __hash_trans(self) -> Tuple[bytes, bytes]:
        b_public_key = self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        content = struct.pack(
            '=id3i', self.version, self.timestamp, len(b_public_key), len(self.ipt.b), len(self.opt.b)
        ) + b_public_key + self.ipt.b + self.opt.b + self.signature

        sha = hashlib.sha256()
        sha.update(content)
        return sha.digest(), content

    @classmethod
    def unpack(cls, b: bytes) -> 'Transaction':
        Verify.transaction_checker(b)

        txid = b[:BLENGTH_TXID]

        version, timestamp, len_b_public_key, len_ipt_b, len_opt_b =\
            struct.unpack('=id3i', b[BLENGTH_TXID:BLENGTH_TXID + 4 * BLENGTH_INT + BLENGTH_DOUBLE])

        l = BLENGTH_TXID + 4 * BLENGTH_INT + BLENGTH_DOUBLE
        b_public_key = b[l:l + len_b_public_key]
        public_key = load_der_public_key(b_public_key, default_backend())
        l += len_b_public_key

        ipt_b = b[l:l + len_ipt_b]
        ipt = TransInput.unpack(ipt_b)

        l += len_ipt_b
        opt_b = b[l:l + len_opt_b]
        opt = TransOutput.unpack(opt_b)

        l += len_opt_b
        signature = b[l:]

        transaction = cls(ipt, opt)
        transaction.txid = txid
        transaction.version = version
        transaction.timestamp = timestamp
        transaction.signature = signature
        transaction.b = b
        transaction.length = len(b)
        transaction.public_key = public_key

        return transaction


class Attachment:

    def __init__(self) -> None:
        self.b = b''
        self.content = b''
        self.rdy = False

    def add_data(self, data: bytes):
        if self.rdy is False:
            self.content += data
        else:
            raise ModificationAfterReady

    def ready(self):
        l = struct.pack('=i', len(self.content))
        self.b = l + self.content
        self.rdy = True

    @classmethod
    def unpack(cls, b: bytes) -> 'Attachment':
        Verify.attachment_checker(b)
        l = struct.unpack('=i', b[:BLENGTH_INT])[0]
        at = cls()
        at.add_data(b[BLENGTH_INT:BLENGTH_INT + l])
        at.ready()
        return at


class BlockData:

    def __init__(self, transaction: List[Transaction], attachment: Attachment) -> None:
        self.trans = transaction
        self.attachment = attachment
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        size = len(self.attachment.b)
        for t in self.trans:
            size += BLENGTH_INT + len(t.b)

        b = bytearray(size)
        p = 0
        b[p:p + len(self.attachment.b)] = bytearray(self.attachment.b)
        p += len(self.attachment.b)
        for t in self.trans:
            # b = b''.join([b, struct.pack('=i', t.length), t.b])
            # b += struct.pack('=i', t.length) + t.b
            b[p:p + BLENGTH_INT] = bytearray(struct.pack('=i', t.length))
            p += BLENGTH_INT
            b[p:p + t.length] = bytearray(t.b)
            p += t.length
        return bytes(b)

    @classmethod
    def unpack(cls, b: bytes) -> 'BlockData':
        Verify.blockdata_checker(b)
        at = Attachment.unpack(b)
        l = struct.unpack('=i', b[:BLENGTH_INT])[0] + BLENGTH_INT

        transaction = []
        while l < len(b):
            trans_length = struct.unpack('=i', b[l:l + BLENGTH_INT])[0]
            l += BLENGTH_INT

            transaction.append(Transaction.unpack(b[l:l + trans_length]))
            l += trans_length

        return cls(transaction, at)


class Block:

    def __init__(self, index: int, timestamp: float, blockdata: BlockData, previous_hash: bytes) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = blockdata
        self.previous_hash = previous_hash
        self.hash, content = self.__hash_block()
        self.b = self.__tobin(content)

    def __hash_block(self) -> Tuple[bytes, bytes]:
        sha = hashlib.sha256()
        content = struct.pack('=id', self.index, self.timestamp) + self.data.b + self.previous_hash
        sha.update(content)
        return sha.digest(), content

    def __tobin(self, content: bytes) -> bytes:
        return self.hash + content

    @classmethod
    def unpack(cls, b: bytes) -> 'Block':
        Verify.block_checker(b)
        blockhash = b[:BLENGTH_BLOCKHASH]
        index, timestamp = struct.unpack('=id', b[BLENGTH_BLOCKHASH: BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE])
        previous_hash = b[-BLENGTH_BLOCKHASH:]
        b_data = b[BLENGTH_BLOCKHASH + BLENGTH_INT + BLENGTH_DOUBLE: -BLENGTH_BLOCKHASH]
        data = BlockData.unpack(b_data)

        block = cls(index, timestamp, data, previous_hash)
        block.hash = blockhash
        block.b = b
        return block


class Blockchain:

    def __init__(self) -> None:
        b = b'\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E'
        priv_key = load_der_private_key(
            b'0\x81\x84\x02\x01\x000\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x04m0k\x02\x01\x01\x04 \xa6qo\xd3\x95}e\xeb\x0f\xa2\xc3U\xa5\xf2v\x85\x19\xbc@\xf7\xfd\xcb^\xa2\xe3\x96N\xff\nh\xd0\x85\xa1D\x03B\x00\x04\xecm\xa8\x92U@;\xb3\xe6\x90\xec\x05+*\x11-\x16b\x8e\xba\xe5\x12\xb4\x93x\xea\xce\x11\xccNPq\xb5\xcb\x08\xc6`\xb2\xd3Y]o\xbciz\xad\xd2\xf4\xc3\x1c,\xaa\x19xs{\x8c\xa9a\xc7\x03\xcb\x18^',
            None,
            default_backend()
        )
        ipt = TransInput([(b, 0)], b)
        opt = TransOutput([(0, 0, 0, b)])
        trans = Transaction(ipt, opt)
        trans.ready(priv_key)
        at = Attachment()
        at.add_data(b)
        at.ready()
        bd = BlockData([trans], at)
        block = Block(0, 0, bd, b)
        block.hash = b
        self.chain = [block]

    def add_block(self, block: Block) -> None:
        Verify.add_block_verifier(self.chain[-1], block)
        self.chain.append(block)


class Verify:  # todo: logical verifier need to be implemented
    def __init__(self):
        pass

    '''
    Check if a block refers correct previous block's hash
    '''
    @staticmethod
    def add_block_verifier(prev_block: Block, block: Block):
        # if block.previous_hash != prev_block.hash:
        #     raise PreviousBlockHashError
        pass

    @staticmethod
    def __hash_checker(data: bytes, hash_: bytes) -> bool:
        sha = hashlib.sha256()
        sha.update(data)
        return sha.digest() == hash_

    @staticmethod
    def block_checker(b: bytes):
        if Verify.__hash_checker(b[32:], b[:32]) is False:
            raise BlockHashError()

    @staticmethod
    def trans_input_checker(b: bytes):
        pass

    @staticmethod
    def trans_output_checker(b: bytes):
        pass

    @staticmethod
    def transaction_checker(b: bytes):
        if Verify.__hash_checker(b[BLENGTH_TXID:], b[:BLENGTH_TXID]) is False:
            raise TransactionHashError()

    @staticmethod
    def attachment_checker(b: bytes):
        pass

    @staticmethod
    def blockdata_checker(b: bytes):
        pass


