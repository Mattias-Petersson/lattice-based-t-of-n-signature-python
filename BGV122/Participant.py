import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, CommitOpen, NameData, SecretSharePoly


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

    def reconstruct(self, shares: list[SecretSharePoly]):
        recon = self.secret_share.reconstruct_poly(shares)
        return NameData(self.name, recon == self.s)

    def __commit_to_shares(self, share) -> tuple[NameData, NameData]:
        comm = NameData(share.name, self.__commit(share.share.p))
        c = NameData(share.name, self.comm_scheme.commit(comm.data))
        return comm, c

    def check_open(self):
        c = dict()
        for i in self.others["c_s_bar"]:
            for j in i.data:
                [c[j.name]] = c.get(j.name, []) + [j.data]
        for i in self.others["coms_s_bar"]:
            for j in i.data:
                if not self.comm_scheme.open(CommitOpen(c[j.name], j.data)):
                    raise ValueError(
                        f"User {self.name} did not get a proper opening for {j.name}"
                    )

    def reconstruct_b(self):
        raise NotImplementedError()

    def bar_vars(self) -> NameData:
        """
        Commits to each secret share s and e, as well as calculate b for these
        as a * s + p * e.
        """
        calc_b_bar = lambda s, e: self.sum_a * s + self.p * e
        add_to_vals = lambda name, value: vals.get(name, []) + [value]
        to_tuple = lambda name: tuple[NameData, ...](vals[name])
        vals = dict()
        for s, e in zip(self.others["shares_s"], self.others["shares_e"]):
            if s.name != e.name:
                raise ValueError(
                    "Index j does not map to the same user when creating b_bar."
                )
            vals["b_bars"] = add_to_vals(
                "b_bars", NameData(s.name, calc_b_bar(s.share.p, e.share.p))
            )
            s_temp = self.__commit_to_shares(s)
            vals["coms_s"] = add_to_vals("coms_s", s_temp[0])
            vals["c_s"] = add_to_vals("c_s", s_temp[1])
            e_temp = self.__commit_to_shares(e)
            vals["coms_e"] = add_to_vals("coms_e", e_temp[0])
            vals["c_e"] = add_to_vals("c_e", e_temp[1])

        self.b_bar = to_tuple("b_bars")
        self.coms_s_bar = to_tuple("coms_s")
        self.c_s_bar = to_tuple("c_s")
        self.coms_e_bar = to_tuple("coms_e")
        self.c_e_bar = to_tuple("c_e")

        return NameData(self.name, self.b_bar)
