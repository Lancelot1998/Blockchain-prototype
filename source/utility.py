from typing import List, Tuple, NewType, Iterator


def n_bytes(b: bytes, n: int) -> List[bytes]:
    return list(map(bytes, list(zip(*[iter(b)] * n))))