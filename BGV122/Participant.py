import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, NameData, SecretSharePoly, SecretShareSplit


class Participant:
    def __init__(
        self, comm_scheme: CommitmentScheme, secret_share: SecretShare
    ):
        self.name = (
            np.random.choice(["Alice", "Bob"])
            + "_"
            + str(np.random.randint(1000))
        )
        self.hash = lambda x: self.polynomial.hash(self.comm_scheme.kappa, x)
        self.gaussian = lambda n: self.polynomial.gaussian_array(
            n=n, sigma=self.comm_scheme.sigma
        )

        self.p = 2029
        self.comm_scheme = comm_scheme
        self.secret_share = secret_share
        self.polynomial = self.comm_scheme.polynomial
        self.cypari = self.comm_scheme.cypari

        self.h_b: tuple[NameData, ...]
        self.a = self.polynomial.uniform_element()
        self.a_hash = self.hash(self.a)
        self.others = dict()

    def share_attr(self, attr: str):
        if not hasattr(self, attr):
            raise ValueError(
                f"No such attribute accepted by participant: {attr}"
            )
        return NameData(self.name, getattr(self, attr))

    def share_others_attr(self, attr: str):
        return NameData(self.name, self.others[attr])

    def recv_from_other(self, attr: str, data):
        self.others[attr] = data

    def compare_a_hash(self) -> NameData:
        for a in self.others["a"]:
            [hash_to_compare] = list(
                filter(lambda x: x.name == a.name, self.others["a_hash"])
            )
            if self.cypari(self.hash(a.data) != hash_to_compare.data):
                return NameData(a.name, False)
        return NameData(self.name, True)

    def make_b(self):
        self.sum_a = self.a + sum([i.data for i in self.others["a"]])
        self.s = self.gaussian(1)
        self.e = self.gaussian(1)
        self.b = self.cypari(self.sum_a * self.s + self.p * self.e)
        self.b_hash = self.hash(self.sum_a * self.s + self.p * self.e)

    def __commit(self, commitment):
        return self.comm_scheme.commit(
            Commit(commitment, self.comm_scheme.r_commit())
        )

    def reconstruct(self, shares: list[SecretSharePoly]):
        recon = self.secret_share.reconstruct_poly(shares)
        return NameData(self.name, recon == self.s)

    def bar_vars(self) -> NameData:
        calc_b_bar = lambda s, e: self.sum_a * s + self.p * e
        b_bars: list[NameData] = []
        coms_s: list[NameData] = []
        coms_e: list[NameData] = []
        for s, e in zip(self.others["s"], self.others["e"]):
            if s.name != e.name:
                raise ValueError(
                    "Index j does not map to the same user when creating b_bar."
                )

            b_bars += NameData(s.name, calc_b_bar(s.share.p, e.share.p))
            coms_s += NameData(s.name, self.__commit(s.share.p))
            coms_e += NameData(e.name, self.__commit(e.share.p))

        self.b_bar = tuple(b_bars)
        self.coms_s = tuple(coms_s)
        self.coms_e = tuple(coms_e)
        return NameData(self.name, self.b_bar)
