# -*- coding: utf-8 -*-
"""
    blockchain
    ~~~~~~~~~~

    Implements blockchain data structure and rules of validation

    :author: hank
"""

import hashlib
import time
import struct
from typing import List, Tuple, NewType
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import \
    Encoding, PublicFormat, load_pem_public_key, load_der_private_key
from cryptography.hazmat.backends import default_backend
from source.utility import n_bytes
from source.errors import *
from cryptography.hazmat.primitives import hashes, hmac
from enum import Enum, unique
from functools import reduce
import queue
import threading

CPU = NewType('CPU', int)
RAM = NewType('RAM', int)
BANDWIDTH = NewType('BANDWIDTH', int)
ASSET = NewType('ASSET', float)
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

    def __init__(self, trans_output: List[Tuple[ASSET, PUBLIC_KEY_HASH]]) -> None:
        self.content = trans_output
        self.b = self.__tobin()

    def __tobin(self) -> bytes:
        b = bytes()
        for opt in self.content:
            b += struct.pack('=d', opt[0]) + opt[1]
        return b

    def __getitem__(self, item) -> Tuple[ASSET, PUBLIC_KEY_HASH]:
        return self.content[item]

    @classmethod
    def unpack(cls, b: bytes) -> 'TransOutput':
        Verify.trans_output_checker(b)
        b_content = n_bytes(b, BLENGTH_DOUBLE + BLENGTH_PUBLIC_KEY_HASH)
        content = list(
            map(lambda i: tuple((*list(struct.unpack('=d', i[:BLENGTH_DOUBLE])), i[-BLENGTH_PUBLIC_KEY_HASH:])),
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
        b_public_key = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
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
        public_key = load_pem_public_key(b_public_key, default_backend())


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


class UTXOTable:
    """
    A table maintains the states of UTXO
    """
    def __init__(self):
        self.utxo = dict()
        self.mutex = threading.Lock()

    def add(self, transaction: Transaction) -> None:
        """
        add all outputs of a transaction to the table
        :param transaction: a transaction
        :return: None
        """
        with self.mutex:
            for index, opt in zip(range(len(transaction.opt.content)), transaction.opt.content):
                self.utxo[(transaction.txid, index)] = {'amount': opt[0],
                                                        'to': opt[1]}

    def exist(self, utxo: Tuple[bytes, int]) -> bool:
        """
        return if the utxo exists in the table
        :param utxo: tuple(txid, index)
        :return: True | False
        """
        with self.mutex:
            return utxo in self.utxo

    def delete(self, transaction: Transaction) -> None:
        """
        delete UTXOs that transaction referenced from the table
        :param transaction: a transaction
        :return: None
        """
        with self.mutex:
            for ipt in transaction.ipt.content:
                del self.utxo[ipt]

    def info(self, utxo: Tuple[bytes, int], block: bool = True) -> dict:
        """
        return infomation of an UTXO
        :param utxo: tuple(txid, index)
        :return: dict contain 'amount' and 'to' of the UTXO
        """
        if block:
            with self.mutex:
                return self.utxo[utxo]
        else:
            return self.utxo[utxo]

    def check(self, utxo: Tuple[bytes, int], amount: int, receiver: bytes) -> bool:
        """
        validate the UTXO
        :param utxo: tuple(txid, index)
        :param amount: amount of assets
        :param receiver: the receiver of assets
        :return: True if pass the validation | False if the utxo does not exist or has invalid amount or receiver
        """
        with self.mutex:
            if utxo in self.utxo:
                return self.info(utxo, block=False)['amount'] == amount\
                       and self.info(utxo, block=False)['to'] == receiver
        return False



class Blockchain:
    """
    no password
    b'-----BEGIN PRIVATE KEY-----\n
    MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg64DiDBUkuGC5rrTfH6uy\n
    Ht6vhvHrMHj3Gm64SZtdqtKhRANCAATMIeaIK4vT0ni00F6GGW40qioinPFgXjsj\n
    6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUXZ877DM4C8ELZs2DPVQ\n
    -----END PRIVATE KEY-----\n'
    b'-----BEGIN PUBLIC KEY-----\n
    MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzCHmiCuL09J4tNBehhluNKoqIpzxYF47\n
    I+rGRor1vSKY/s3A3z3O0cWbhXihZm7VWlF2fO+wzOAvBC2bNgz1UA==\n
    -----END PUBLIC KEY-----\n'
    pubkey hash (the first transaction in genesus block pay 42 to this address):
    b'\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80\x10H\xb6\xa1\xfd\x02\xbf'
    """

    def __init__(self) -> None:
        b = b'\xbe\x0e\xa2U\xd6\xc9\xa6\xd6C\xe0\x06\xf5{\x89^4\x1b\xb3\x95z\x04}\xc1\xf8]\xe3\xc6\x82\xdc\xb1\x90E'
        priv_key = load_der_private_key(
            b'0\x81\x84\x02\x01\x000\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x04m0k\x02\x01\x01\x04 '
            b'\xa6qo\xd3\x95}e\xeb\x0f\xa2\xc3U\xa5\xf2v\x85\x19\xbc@\xf7\xfd\xcb^\xa2\xe3\x96N\xff\nh\xd0\x85\xa1D'
            b'\x03B\x00\x04\xecm\xa8\x92U@;\xb3\xe6\x90\xec\x05+*\x11-\x16b\x8e\xba\xe5\x12\xb4\x93x\xea\xce\x11'
            b'\xccNPq\xb5\xcb\x08\xc6`\xb2\xd3Y]o\xbciz\xad\xd2\xf4\xc3\x1c,\xaa\x19xs{\x8c\xa9a\xc7\x03\xcb\x18^',
            None,
            default_backend()
        )
        ipt = TransInput([(b, 0)], b)
        opt = TransOutput([(42, b'\x8b\x8dZ\x80\xde\x82k\xe1>0F\xf4\xbbh\x93\x04\xef\x8e\x9b\xe2\xb2\xd9\xe1\x9c\x80\x10H\xb6\xa1\xfd\x02\xbf')])
        trans = Transaction(ipt, opt)
        trans.ready(priv_key)
        print(trans.txid)

        at = Attachment()
        at.add_data(b)
        at.ready()
        bd = BlockData([trans], at)
        block = Block(0, 0, bd, b)
        block.hash = b

        self.chain = queue.Queue()
        self.chain.put(block)

        self.utxo = UTXOTable()
        for trans in block.data.trans:
            self.utxo.add(trans)

    def add_block(self, block: Block) -> None:
        Verify.add_block_verifier(self.chain.queue[-1], block)
        # todo: update UTXO table
        self.chain.put(block)

    def size(self) -> int:
        return self.chain.qsize()

    def search_block(self, hash: bytes = None, timestamp: float = None, index: int = None) -> Block:
        if hash is not None:
            return [block for block in self.chain.queue if block.hash == hash].pop()

        if timestamp is not None:
            return [block for block in self.chain.queue if block.timestamp == timestamp].pop()

        if index is not None:
            return [block for block in self.chain.queue if block.index == index].pop()

        return None

    def search_transaction(self, txid: bytes = None, timestamp: float = None) -> Transaction:
        for block in self.chain.queue:
            for trans in block:
                if txid is not None:
                    if trans.txid == txid:
                        return trans
                if timestamp is not None:
                    if trans.timestamp == timestamp:
                        return trans


class TransPool:
    """
    the thread-safe pool of transactions
    """

    def __init__(self, chain: Blockchain):
        self.trans = queue.Queue()
        self.utxo = UTXOTable()
        self.chain = chain
        self.ipt = []

    def add(self, transaction) -> bool:
        """add a transaction to the pool"""

        if isinstance(transaction, bytes):
            transaction = Transaction.unpack(transaction)

        """
        The following conditions 2 guarantee that a new transaction can use UTXO in transpool
        (by giving both self.utxo and self.chain.utxo to checkers)
        But this behavior is not recommended (the used UTXO may not exist in all nodes' transpool)
        
        Also the condition 2 does not prevent the double-spending in transpool, e.g.,
                Wrong:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A----|   |--A<-B---|
        |---------|   |--A<-C---|
        |---------|   |---------|
                  OK:
        |-- UTXO--|   |-- pool--|
        |---------|   |---------|
        |----A<-B-|   |---------|
        |---------|   |--A<-C---|
        |---------|   |---------|
        
        because the codes here do not change the UTXO table of the blockchain.
        
        So I use a extra list recording all inputs of transactions that are in the UTXO table of transpool
        and add the condition 3
        """

        if Verify.sig_checker(transaction)\
            and Verify.double_spend_checker([self.utxo, self.chain.utxo], transaction)\
            and Verify.transpool_double_spend_checker(self.ipt, transaction)\
            and Verify.balance_checker([self.utxo, self.chain.utxo], transaction):

            self.utxo.add(transaction)  # add all outputs in transaction to the UTXO table of transpool

            for ipt in transaction.ipt.content:
                self.ipt.append(ipt)

            self.trans.put(transaction)
            return True
        else:
            return False


    def retrieve(self, num: int) -> List[Transaction]:
        """
        get transactions in the pool
        :param num: number of transactions to be retrieved
        :return: a list of transactions
        """
        num = min(self.trans.qsize(), num)

        result = []
        for i in range(num):
            result.append(self.trans.get())

        return result

    def retrieve_serialized(self, num: int) -> List[bytes]:
        """
        get transactions in the pool with serialized format
        :param num:  number of transactions to be retrieved
        :return: a byte string of the retrieved transactions
        """
        return [trans.b for trans in self.retrieve(num)]

    def read(self) -> List[Transaction]:
        """
        read all the transactions in the pool
        :return: a list of transactions
        """
        return list(self.trans.queue)

    def read_serialized(self) -> List[bytes]:
        """
        read all the transactions in the pool
        :return: a list of binary transactions
        """
        return [trans.b for trans in self.read()]


class Verify:  # todo: logical verifier need to be implemented
    def __init__(self):
        pass

    '''
    Check if a block refers correct previous block's hash
    '''
    @staticmethod
    def add_block_verifier(prev_block: Block, block: Block):
        if block.previous_hash != prev_block.hash:
            raise PreviousBlockHashError
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
    def double_spend_checker(utxo_tables: List[UTXOTable], trans: Transaction) -> bool:
        """
        check if the transaction spends one or more outputs twice compared to the given UTXO tables
        :param utxo_tables: List of UTXO tables
        :param trans: a transaction
        :return: True no double spend | False double spend
        """
        for i in trans.ipt.content:
            search = [table.exist(i) for table in utxo_tables]
            if not reduce(lambda x, y: x or y, search):
                print('double')
                return False
        return True

    @staticmethod
    def transpool_double_spend_checker(ipts: List, trans: Transaction) -> bool:
        """
        check if any input of the trans exists in ipts
        :param ipts: a list of inputs
        :param trans: a transaction
        :return: True no double spending | False double spending
        """
        return not reduce(lambda x, y: x or y, [i in ipts for i in trans.ipt.content])

    @staticmethod
    def sig_checker(trans: Transaction) -> bool:
        try:
            trans.public_key.verify(trans.signature,
                                    struct.pack('=f', trans.timestamp) + trans.ipt.b + trans.opt.b,
                                    ec.ECDSA(hashes.SHA256()))
        except(Exception):
            pass
        else:
            return True


    @staticmethod
    def balance_checker(utxo_tables: List[UTXOTable], trans: Transaction) -> bool:
        """
        check the balance between inputs and outputs.
        Note that this function assumes that the trans pass the double spending validation
        and does not check the existence of trans in UTXO
        :param utxo_tables: List of UTXO tables
        :param trans: a transaction
        :return: True if the inputs and outputs balance | False if the inputs and outputs do not balance
        """
        b_pubkey = trans.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sha = hashlib.sha256()
        sha.update(b_pubkey)
        public_key_hash = sha.digest()
        amount = 0

        if public_key_hash != trans.ipt.public_key_hash:
            return False

        for i in trans.ipt.content:
            for table in utxo_tables:
                if table.exist(i):
                    if not table.info(i)['to'] == trans.ipt.public_key_hash:  # check if the UTXO is to this pubkey hash
                        return False
                    amount += table.info(i)['amount']  # get the amount of UTXO

        for opt in trans.opt.content:
            amount -= opt[0]
        if amount != 0:  # inputs and outputs are imbalance
            return False

        return True



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


