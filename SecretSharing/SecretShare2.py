from BDLOP16.CommitmentScheme import CommitmentScheme
from type.classes import TN, SecretSharePoly
from utils.Polynomial import Polynomial
import cypari2
import numpy as np


class SecretShare:
    """
    Class for Shamir secret sharing of polynomials.

    Args:
    tn (TN):                (t, n) tuple of required participants and total participants.
    q (int):                The modulus of the ring.

    """

    def __init__(self, tn: TN, q: int):
        self.t, self.n = tn
        self.q = q
        self.polynomial = Polynomial(self.t, self.q)
        self.cypari: cypari2.pari_instance.Pari = self.polynomial.cypari

    def __generatePoly(self, s):
        """
        Samples t - 1 uniform elements and creates a polynomial out of these, with
        the secret s as the x^0 coefficient such that p(0) = s. We are also limiting
        the coefficient to not be zero.
        """
        [poly] = [
            str(np.random.randint(1, self.q)) + "*x^" + str(self.t - i) + "+"
            for i in range(1, self.t)
        ]
        return self.cypari.Pol(poly + str(s)) * self.cypari.Mod(1, self.q)

    def __share(self, s):
        random_polynomial = self.__generatePoly(s)
        return [self.cypari(random_polynomial)(x=i + 1) for i in range(self.n)]

    def reconstruct(self, res_arr, x_arr):
        norm_sum = lambda j, i: j / (j - i) if i != j else 0
        sum_arr = [sum(norm_sum(j, i) for j in x_arr) for i in x_arr]
        return sum([int(s) * r for s, r in zip(sum_arr, res_arr)])

    def share_poly(self, poly) -> list[SecretSharePoly]:
        """
        Creates a share of polynomials for each participant.
        """
        shares = [self.__share(i) for i in self.polynomial.pol_to_arr(poly)]
        temp = [self.cypari.Pol(list(col)) for col in zip(*shares)]
        return [SecretSharePoly(idx + 1, p) for idx, p in enumerate(temp)]

    def reconstruct_poly(self, r: list[SecretSharePoly]):
        if len(r) > self.t:
            r = r[: self.t]
        contributors = [i.x for i in r]
        rec_arr = [self.polynomial.pol_to_arr(i.p) for i in r]
        polys = [list(col) for col in zip(*rec_arr)]
        ret_arr = [self.reconstruct(i, contributors) for i in polys]
        return self.cypari.Pol(ret_arr) * self.cypari.Mod(1, self.q)


if __name__ == "__main__":
    c = CommitmentScheme()
    s = SecretShare((2, 4), c.q)
    cyp = cypari2.Pari()
    pol = cyp.Pol("x^4 + 3*x^3 + x^2 + 1")
    r = s.share_poly(pol)
    s.reconstruct_poly(r[0])
