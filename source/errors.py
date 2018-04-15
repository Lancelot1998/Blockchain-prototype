# -*- coding: utf-8 -*-
"""
    errors
    ~~~~~~~~~~

    Collection of errors

    :author: hank
"""

class BlockchainError(Exception):
    pass


class BlockHashError(BlockchainError):
    pass


class TransactionHashError(BlockchainError):
    pass


class ModificationAfterReady(BlockchainError):
    pass


class PreviousBlockHashError(BlockchainError):
    pass
