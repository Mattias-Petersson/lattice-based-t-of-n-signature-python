import math
import cypari2
from type.classes import Commit, CommitOpen

from utils.Polynomial import Polynomial


class TDCommitmentScheme:
    """
    A trapdoor commitment scheme. q and n are constant values no matter what
    level of NIST security level we use in accordance with Dilithium
    specifications.

    N is a power of two, defining the degree to f(x)
    q is the prime modulus
    s_bar is ?
    s is ?
    w is ?
    B is the maximum L2 norm of signature share z_j in R^(l + k) for j in [n]
    (k, l) is the shape of A.
    """

    def __init__(self):
        self.N: int = 256
        self.q: int = 8380417
        self.polynomial = Polynomial(self.N, self.q)
        self.cypari = self.polynomial.cypari

        """The l_1 norm is referred to as tau in the Dilithium docs. We choose to
        call it kappa to be consistent across files."""
        self.kappa = 49

        self.s_bar = 0  # Not correct
        self.s = 0  # Not correct
        self.k, self.l = 6, 5
        self.w = 0  # Not correct.
        self.B = self.__make_B()
        self.Â = self.__make_A((2, self.l + 2 * self.w))

    def __make_A(self, shape: tuple[int, int]) -> cypari2.gen.Gen:
        """
        Â is the commitment key and has shape (2, l+2w)
        overline{A} is needed for a trapdoor commitment key, shape (2, l)
        A_{1, 1} is sampled as a small uniform invertible element of R_q.
        A_{2, 1} = 0, A_{2, 2} = 1
        All other indices should be sampled uniformly from the ring R_q.
        """
        A = self.polynomial.uniform_array(n=shape)
        A[0][0] = self.polynomial.challenge(self.kappa)
        A[1][0], A[1][1] = 0, 1
        return A

    def __make_B(self) -> int:
        """
        Bound B for verification. Needs to be large enough to accomodate
        valid commits, and small in comparison to q.
        """
        C = 1 / math.sqrt(2 * math.pi)
        return int(
            C
            * self.s
            * math.sqrt(self.N)
            * (math.sqrt(self.l + 2 * self.w) + 1)
        )

    def __make_r(
        self, shape: int | tuple[int, int], sigma, bound: int | None = None
    ) -> cypari2.gen.Gen:
        arr = lambda: self.polynomial.gaussian_array(shape, sigma)
        r = arr()
        if bound:
            while self.polynomial.l2_norm(r) > self.B:
                r = arr()
            return r
        return r

    def __Ar_with_msg(
        self, c: Commit
    ) -> tuple[cypari2.gen.Gen, cypari2.gen.Gen]:
        Ar = self.cypari.Mat(self.Â * self.cypari.mattranspose(c.r))
        zeroes = self.cypari.matconcat(
            self.cypari.mattranspose([self.cypari.Pol("0"), c.m])
        )
        return Ar, zeroes

    def make_commit(self) -> Commit:
        m = self.polynomial.uniform_element()
        r = self.__make_r(self.l + 2 * self.w, self.s, self.B)
        return Commit(m, r)

    def com(self, c: Commit):
        """
        Commits to an x in R_q and returns Â * r + [0 x]~

        Args:
        c: A commitment, with x a polynomial in R_q,
        and r a discrete Gaussian vector of length l+2w.

        Returns:
        A commitment c from x, r.
        """
        Ar, zeroes = self.__Ar_with_msg(c)
        return self.cypari(Ar + zeroes)

    def open(self, com: CommitOpen) -> bool:
        """
        Returns whether the commitment c matches the randomness
        r and message m that was sent in via the com object.

        Args:
        com: A commitment opening, consisting of a function f,
        a commitment c, a message m and randomness r.

        Returns:
        True if the commitment was valid, False otherwise.
        """
        Ar, zeroes = self.__Ar_with_msg(com)
        rhs = self.cypari(Ar + zeroes)
        return bool(self.cypari(com.c == rhs))

    def tc_gen(self):
        A_ol = self.__make_A((2, self.l))
        R = self.polynomial.gaussian_array(
            (self.l, 2 * self.w), sigma=self.s_bar
        )
        return (0, 0)

    def t_com(self) -> list[cypari2.gen.Gen]:
        """
        Return a uniformly random commitment f from R_q^{2x1}.
        """
        return self.polynomial.uniform_array((2, 1))

    def eqv(self, td, com, m):
        """
        Uses the Micciancio-Peikert algorithm (MP12 algorithm 3).
        """
        return 0


if __name__ == "__main__":
    b = TDCommitmentScheme()
    com = b.make_commit()
    test = b.com(com)
    test2 = b.open(CommitOpen(test, 0, commit=com))
    print(test2)
