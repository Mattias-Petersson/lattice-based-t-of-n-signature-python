from abc import ABC, abstractmethod

import numpy as np

from Models.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from type.classes import NameData


class Participant(ABC):
    @abstractmethod
    def __init__(
        self,
        comm_scheme: CommitmentScheme,
        BGV_comm_scheme: CommitmentScheme,
        secret_share: SecretShare,
        Q: int,
        q: int,
        p: int,
        N: int,
        x: int,
    ):
        self.name = (
            np.random.choice(["Alice", "Bob"])
            + "_"
            + str(np.random.randint(1000))
        )
        self.q = q
        self.p = p
        self.N = N
        # what x that is associated with this participant's secret shares.
        self.x = x
        self.comm_scheme = comm_scheme
        self.BGV_comm_scheme = BGV_comm_scheme
        self.secret_share = secret_share
        self.polynomial = self.comm_scheme.polynomial
        self.BGV_polynomial = self.BGV_comm_scheme.polynomial
        self.hash = lambda x: self.polynomial.hash(self.comm_scheme.kappa, x)
        self.BGV_hash = lambda x: self.BGV_polynomial.hash(
            self.BGV_comm_scheme.kappa, x
        )
        # 39 chosen to match Dilithium specs for number of +/- 1 in challenge.
        self.ternary = lambda: self.BGV_polynomial.challenge(39)
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
