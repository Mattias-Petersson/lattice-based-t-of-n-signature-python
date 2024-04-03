import math
import cypari2
from type.classes import Commit, CommitOpen

from utils.Polynomial import Polynomial


class DOTT:
    """
    An implemention of a trapdoor commitment scheme by Damgård, Orlandi,
    Takahashi, and Tibouchi.
    """

    def __init__(self):
        def make_B() -> int:
            """
            Bound B for verification. Needs to be large enough to accomodate
            valid commits, and small in comparison to q.

            In the paper, B can be set to C*s*sqrt(N) * (sqrt(l + 2w) + 1) in
            the correctness property. It can also be instantiated as
            Theta(N^2 * log^3(N)). This method does the former of the two.
            """
            C = 1 / math.sqrt(2 * math.pi)
            return int(
                C
                * self.s
                * math.sqrt(self.N)
                * (math.sqrt(self.l + 2 * self.w) + 1)
            )

        self.N: int = 256
        self.q: int = 8380417
        self.polynomial = Polynomial(self.N, self.q)
        self.cypari = self.polynomial.cypari

        """The l_1 norm is referred to as tau in the Dilithium docs. We choose to
        call it kappa to be consistent across files."""
        self.kappa = 49

        self.s = self.N ** (3 / 2) * math.log2(self.N)
        self.s_bar = self.N
        self.k, self.l = 6, 5
        self.w = math.ceil(math.log2(self.q))

        self.B = make_B()
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
        A[1][0], A[1][1] = self.cypari.Pol("0"), self.cypari.Pol("1")
        return A

    def __make_r(self, n: int, sigma, bound: int) -> cypari2.gen.Gen:
        return self.polynomial.guassian_bounded_array(n, sigma, bound)

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

    def get_r(self):
        return self.__make_r(self.l + 2 * self.w, self.s, self.B)

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
        return Ar + zeroes

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
        for r in com.r:
            if (
                self.polynomial.l2_norm(r) > self.B
            ):  # TODO: Make this work, as pol_to_arr crashes
                return False
        Ar, zeroes = self.__Ar_with_msg(com)
        return com.c == Ar + zeroes

    def tc_gen(self):
        """
        Keygen with a trapdoor. Samples an R from a Gaussian distribution
        of shape (l, 2w) and outputs it as the trapdoor td. The commitment
        key is Â= [A | (G - Ar)] or tck. Both of these are returned as a tuple
        from the method.

        """

        def make_G() -> list:
            concat = lambda lst1, lst2: self.cypari.concat(lst1, lst2)
            range_w = range(self.w)
            powers_of_two_pol = [i**2 for i in range_w]
            zeroes_pol = [0 for _ in range_w]

            row_one = concat(powers_of_two_pol, zeroes_pol)
            row_two = concat(zeroes_pol, powers_of_two_pol)

            return self.cypari.matrix(2, 2 * self.w, (*row_one, *row_two))

        A_ol = self.__make_A((2, self.l))
        R = self.polynomial.gaussian_array(
            (self.l, 2 * self.w), sigma=self.s_bar
        )
        G = make_G()
        Ar = A_ol * R
        Â = self.cypari.concat(A_ol, G - Ar)
        return (R, Â)

    def t_com(self) -> list[cypari2.gen.Gen]:
        """
        Return a uniformly random commitment f from R_q^{2x1}.
        """
        return self.polynomial.uniform_array((2, 1))

    def eqv(self, td, com, m):
        """
        Uses the Micciancio-Peikert algorithm (MP12 algorithm 3).
        """
        raise NotImplementedError("Not implemented for this version.")
