from abc import ABC, abstractmethod

import numpy as np

from SecretSharing.SecretShare import SecretShare
from type.classes import NameData


class Participant(ABC):
    @abstractmethod
    def __init__(
        self,
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
        # All participants other than self.
        self.participant_names = []
        self.secret_share = secret_share
        self.others = dict()

    @abstractmethod
    def hash(self, x):
        pass

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
