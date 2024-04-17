from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from GKS23.MultiCounter import MultiCounter
from type.classes import TN, SecretSharePoly, poly
from utils.Polynomial import Polynomial
import numpy as np
import math


class SecretShare:
    """
    Class for Shamir secret sharing of polynomials.

    Args:
    tn (TN):                (t, n) tuple of required participants and total participants.
    q (int):                The modulus of the ring.

    """

    def __init__(self, tn: TN, q: int, counter: MultiCounter):
        self.t, self.n = tn
        if self.t > self.n:
            raise ValueError("Got t larger than n in secret share.")
        self.q = q
        self.counter = counter
        self.polynomial = Polynomial(self.counter, self.t, self.q)
        self.cypari = self.polynomial.cypari

    def __generatePoly(self, s: poly) -> poly:
        """
        Samples t - 1 uniform elements and creates a polynomial out of these, with
        the secret s as the x^0 coefficient such that p(0) = s. We are also limiting
        the coefficient to not be zero.
        """
        poly_arr = [
            str(np.random.randint(1, self.q)) + "*x^" + str(self.t - i) + "+"
            for i in range(1, self.t)
        ]
        poly = "".join(poly_arr) + str(s)
        self.counter.inc_mod()
        return self.cypari.Pol(poly) * self.cypari.Mod(1, self.q)

    def __share(self, s):
        random_polynomial = self.__generatePoly(s)
        return [self.cypari(random_polynomial)(x=i + 1) for i in range(self.n)]

    def lagrange(self, lst) -> list[int]:
        norm_sum = lambda j, i: (
            (j * pow(j - i, self.q - 2, self.q)) if i != j else 1
        )
        return [math.prod(norm_sum(j, i) for j in lst) for i in lst]

    def __reconstruct(self, res_arr, x_arr):
        lagrange = self.lagrange(x_arr)
        return sum([s * r for s, r in zip(lagrange, res_arr)])

    def share_poly(self, poly) -> list[SecretSharePoly]:
        """
        Creates a share of polynomials for each participant.
        """
        shares = [self.__share(i) for i in self.polynomial.pol_to_arr(poly)]
        temp = [self.cypari.Pol(list(col)) for col in zip(*shares)]
        return [SecretSharePoly(idx + 1, p) for idx, p in enumerate(temp)]

    def reconstruct_poly(self, r: list[SecretSharePoly]):
        """
        Reconstructs a polynomial using a list of secret shares.
        If the list is too large, we simply take the first t elements rather
        than report an error. If the list is too small the returned polynomial
        will not be equivalent to the one that was shared.
        """
        if len(r) > self.t:
            r = r[: self.t]
        contributors = [i.x for i in r]
        rec_arr = [self.polynomial.pol_to_arr(i.p) for i in r]
        polys = [list(col) for col in zip(*rec_arr)]
        ret_arr = [self.__reconstruct(i, contributors) for i in polys]
        self.counter.inc_mod()
        return self.cypari.Pol(ret_arr) * self.cypari.Mod(1, self.q)
