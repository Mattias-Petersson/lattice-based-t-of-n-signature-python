import abc
from abc import abstractmethod
from typing import Iterable

from Models.Participant import Participant
from type.classes import NameData


class Controller(abc.ABC):
    @abstractmethod
    def __init__(self, participants: Iterable[Participant]):
        self.participants = participants
        self.names = [i.name for i in self.participants]

    def recv_value(self, attr):
        try:
            return [i.share_attr(attr) for i in self.participants]
        except Exception as e:
            raise ValueError(
                f"Invalid attribute name in class Participant: {attr}, {e}"
            )

    def recv_value_shared(self, attr):
        return tuple(i.share_others_attr(attr) for i in self.participants)

    def share_data(self, attr, data):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name != i.name, data))
            i.recv_from_other(attr, res)

    def share_partials(self, attr):
        data = self.recv_value(attr)
        shares = dict()
        for i in data:
            for j, name in zip(i.data, self.names):
                shares[name] = shares.get(name, []) + [NameData(i.name, j)]
        for part in self.participants:
            part.recv_from_other(attr, shares[part.name])

    def recv_share(self, attr_name: str):
        return self.share_data(attr_name, self.recv_value(attr_name))

    def assert_value_matches_hash(self, attr):
        """
        Takes in the hash of an attr all participants, then all values. Then each
        participant does a check if the hashes they received correspond to the
        value they received when hashed.
        """
        self.recv_share(attr + "_hash")
        self.recv_share(attr)
        for i in self.participants:
            if not i.compare_hash(attr).data:
                raise ValueError(
                    f"Aborting. {attr} and {attr}_hash do not match for user {i.name}"
                )
