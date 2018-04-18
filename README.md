# Blockchain prototype

## Vision

Develop a blockchain prototype with basic mechanisms, such as Proof-of-Work,
double-spending validation, and balance validation of transactions. These mechanisms
are absense in many blockchain demos that I can find. I will implement some of 
my research idea on this project also.



## Components
- chainbase (developing)

    The backend of blockchain. Provide a pool of transactions and blockchain services. 

- webchain (developing)

    a user interface to operator the backend.

- conchain (future)

    the consensus component.

## Tests

### chainbase_test::test_000_trans_write

The first (genesis) block contains a transaction that pays 42 to the address that corresponds to the following private key. This test case first use this private key to issue and submit a transaction which pays 7 for 6 random addresses. This transaction is valid and stays in the pool of transactions. Then the test try to issue a new transaction. Because the 42 assets of the following private key were used up, the new transaction is invalid. Finally, the test pays 7 from random address 1 to address 2.

## How to use

Requirements: Python 3.6+, cryptography, flask
> pip install -r requirements.txt

Export the path to package:
> export PYTHONPATH=/path/to/bc

Run chainbase:
```
cd source
python chainbase.py
```

Replace the related content in test/chainbase_test.py
```
cd test
python -m unittest chainbase_test.py
```