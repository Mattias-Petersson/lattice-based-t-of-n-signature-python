import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, NameData, SecretSharePoly
import itertools


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

    def compare_hash(self, attr) -> NameData:
        for val in self.others[attr]:
            [hash_to_compare] = list(
                filter(
                    lambda x: x.name == val.name, self.others[attr + "_hash"]
                )
            )
            if self.hash(val.data) != hash_to_compare.data:
                return NameData(val.name, False)
        return NameData(self.name, True)

    def make_b(self):
        self.sum_a = self.a + sum([i.data for i in self.others["a"]])
        self.s, self.e = self.gaussian(1), self.gaussian(1)

        self.com_s = self.__commit(self.s)
        self.c_s = self.comm_scheme.commit(self.com_s)

        self.com_e = self.__commit(self.e)
        self.c_e = self.comm_scheme.commit(self.com_e)

        self.b = self.sum_a * self.s + self.p * self.e
        self.b_hash = self.hash(self.b)

    def __commit(self, commitment):
        """
        Returns a commit object of the commitment and a randomness r. Can
        be used to commit with a commitment scheme and return c.
        """
        return Commit(commitment, self.comm_scheme.r_commit())

    def make_secrets(self):
        def make_b(s, e):
            if s.x != e.x:
                raise ValueError()
            return SecretSharePoly(s.x, self.sum_a * s.p + self.p * e.p)

        add_val = lambda name, val: vals.get(name, []) + [val]
        to_tuple = lambda attr: tuple(vals[attr])

        self.s_bar = self.secret_share.share_poly(self.s)
        self.e_bar = self.secret_share.share_poly(self.e)
        vals = dict()
        for s, e in zip(self.s_bar, self.e_bar):
            vals["b_bar"] = add_val("b_bar", make_b(s, e))

            com_s = self.__commit(s.p)
            vals["coms_s_bar"] = add_val("coms_s_bar", com_s)
            vals["c_s_bar"] = add_val("c_s", self.comm_scheme.commit(com_s))

            com_e = self.__commit(e.p)
            vals["coms_e_bar"] = add_val("coms_e_bar", com_e)
            vals["c_e_bar"] = add_val("c_e", self.comm_scheme.commit(com_e))

        self.b_bar = to_tuple("b_bar")
        self.coms_s_bar = to_tuple("coms_s_bar")
        self.c_s_bar = to_tuple("c_s_bar")
        self.coms_e_bar = to_tuple("coms_e_bar")
        self.c_e_bar = to_tuple("c_e_bar")

    def reconstruct(self, data, t):
        """
        Attempts to reconstruct this participant's own b, using the shares
        provided to them from the BGV class in the data param. All possible
        combinations are tried, as all should return true. If any combination
        returns false we print out the user for which the process failed, and
        which key shares were responsible.
        """
        combs = list(itertools.combinations([i for i in data], t))

        for c in combs:
            pol = self.secret_share.reconstruct_poly([i.data for i in c])
            if pol != self.b:
                raise ValueError(
                    "Aborting. Reconstructing b failed for user {}, reconstructing polynomials for users: {}".format(
                        self.name, [i.name for i in c]
                    )
                )
