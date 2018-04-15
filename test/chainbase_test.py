# -*- coding: utf-8 -*-
"""
    block_test
    ~~~~~~~~~~

    general test of chain services

    :author: hank
"""
import socket
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
import hashlib
from source.blockchain import TransInput, TransOutput, Transaction
import time
import struct
from source.transfer import send_handler, batch_parser, MsgType, recv_parser


class BlockChainTestCase(unittest.TestCase):

    def test_000_trans_write(self):
        """
        The first (genesis) block contains a transaction that pays 42 to the address that corresponds to the
        following private key. This test case first use this private key to issue and submit a transaction
        which pays 7 for 6 random addresses. This transaction is valid and stays in the pool of transactions.
        Then the test try to issue a new transaction. Because the 42 assets of the following private key were
        used up, the new transaction is invalid. Finally, the test pays 7 from random address 1 to address 2.
        """

        tinput = [
            # replace the first parameter with the hash that chainbase generates
            (b'"K\x02\x18\xd4_C\x1fp\x15\x94\x11*?J\x8a\xc6\x1aoT\x05\xee`g\xcc=b{r\x86\xe0\xf5', 0)
        ]
        # replace the following connection address with the address that chainbase generates
        socketfile = '/tmp/0.2026088804904984'


        private_key1 = load_pem_private_key(b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0w'
                                            b'awIBAQQg64DiDBUkuGC5rrTfH6uy\nHt6vhvHrMHj3Gm64SZtdqtKhRANCAATMIea'
                                            b'IK4vT0ni00F6GGW40qioinPFgXjsj\n6sZGivW9Ipj+zcDfPc7RxZuFeKFmbtVaUX'
                                            b'Z877DM4C8ELZs2DPVQ\n-----END PRIVATE KEY-----\n',
                                           None, default_backend())
        public_key = b'-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzCHmiCuL09J4tNBehhluNKoqIpzx' \
                     b'YF47\nI+rGRor1vSKY/s3A3z3O0cWbhXihZm7VWlF2fO+wzOAvBC2bNgz1UA==\n-----END PUBLIC KEY-----\n'
        sha = hashlib.sha256()
        sha.update(public_key)
        public_key_hash = sha.digest()


        T1 = TransInput(tinput, public_key_hash)

        public_key_hash = []
        private_keys = []
        public_keys = []

        for i in range(6):
            private_key = ec.generate_private_key(ec.SECP256K1, default_backend())
            private_keys.append(private_key)

            public_key = private_key.public_key()
            public_key = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            public_keys.append(public_key)

            sha = hashlib.sha256()
            sha.update(public_key)
            public_key_hash.append(sha.digest())

        toutput = [(7, public_key_hash[i]) for i in range(6)]
        T2 = TransOutput(toutput)

        T = Transaction(T1, T2)
        T.ready(private_key1)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the valid transaction

            s.connect(socketfile)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)  # the chainbase returns OK

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            # submit the same transaction, but it is invalid this time

            s.connect(socketfile)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_ERROR)  # the chainbase returns ERROR

        """
        construct a second valid transaction, which pay 7 from random address 1 to random address 2 
        """
        private_key = private_keys[0]
        public_key = public_keys[0]
        public_key_hash1 = public_key_hash[0]

        T1 = TransInput([(T.txid, 0)], public_key_hash1)

        toutput = [(7, public_key_hash[1])]
        T2 = TransOutput(toutput)

        T = Transaction(T1, T2)
        T.ready(private_key)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # submit the second valid transaction

            s.connect(socketfile)
            payload = send_handler(MsgType.TYPE_TRANS_WRITE, T.b)
            s.sendall(payload)
            header, length, msgtype, content = recv_parser(s)

            self.assertEqual(content, b'')
            self.assertEqual(length, 0)
            self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)  # the chainbase returns OK


    # def test_001_trans_read(self):
    #
    #
    #
    #
    #     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    #         s.connect('/home/cx/Desktop/ss')
    #         s.sendall(send_handler(MsgType.TYPE_TRANS_READ, b''))
    #         header, length, msgtype, content = recv_parser(s)
    #         content = batch_parser(content)
    #
    #
    #         for i in content:
    #             Transaction.unpack(i)
    #         self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)
    #         self.assertEqual(len(content), 3)
    #
    # def test_002_trans_retrieve(self):
    #
    #     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    #         s.connect('/home/cx/Desktop/ss')
    #         s.sendall(send_handler(MsgType.TYPE_TRANS_RETRIEVE, struct.pack('=i', 1)))
    #         header, length, msgtype, content = recv_parser(s)
    #         content = batch_parser(content)
    #
    #
    #         for i in content:
    #             Transaction.unpack(i)
    #         self.assertEqual(msgtype, MsgType.TYPE_RESPONSE_OK)
    #         self.assertEqual(len(content), 1)