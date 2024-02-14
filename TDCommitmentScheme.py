from typing import Tuple

# Temporary types to ensure that typing works.
type CommitmentKey = int
type Com = int
type Tck = int
type Td = int


class TDCommitmentScheme:
    """
    A trapdoor commitment scheme. q and n are constant values no matter what
    level of NIST security level we use in accordance with Dilithium
    specifications.

        :param q int: The ring modulus, default 2^23 - 2^13 + 1.
        :param n int: The degree of the irreducible polynomial, default 256.

    """

    def __init__(self, q: int = 8380417, N: int = 256):
        print(q, N)

    def c_gen(self) -> CommitmentKey:
        return 0

    def com(self, m, msg) -> Com:
        return 0

    def open(self, com, r, msg) -> bool:
        # return True if (com, r, msg) is valid, False otherwise
        return False

    def tc_gen(self) -> Tuple[Tck, Td]:
        return (0, 0)

    def t_com(self, td) -> Com:
        # same type of com? Look into.
        return 0

    def eqv(self, td, com, m):
        return 0
