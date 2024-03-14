from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.Participant import Participant
from type.classes import NameData, SecretShareSplit


class BGV:
    def __init__(self, n: int = 4, q: int = 2**32 - 527, N: int = 1024):
        self.n = n
        self.q = q
        self.N = N
        self.comm_scheme = CommitmentScheme()
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((3, self.n), self.q)
        self.participants: tuple[Participant, ...] = tuple(
            Participant(self.comm_scheme, self.secret_share) for _ in range(n)
        )
        self.names = [i.name for i in self.participants]

    def __recv_data(self, fn: str) -> tuple[NameData, ...]:
        """
        Recevies data from all participants, using the sent in function.
        """
        if not (
            hasattr(Participant, fn) and callable(getattr(Participant, fn))
        ):
            raise ValueError(
                f"Invalid function name sent in to receive data: {fn}."
            )

        return tuple(getattr(i, fn)() for i in self.participants)

    def __share_data(
        self,
        data: tuple[NameData, ...] | tuple[SecretShareSplit, ...],
        attr: str,
    ):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name != i.name, data))
            try:
                setattr(i, attr, res)
            except Exception as e:
                print(
                    f"Invalid attribute name in class Participant: {attr}, {e}"
                )

    def __recv_share(self, fn, attr):
        self.__share_data(self.__recv_data(fn), attr)

    def __assert_a_with_hash(self):
        self.__recv_share("a_hash", "hashes")
        self.__recv_share("own_a", "other_a")
        for i in self.__recv_data("compare_a_hash"):
            if not i.data:
                raise ValueError(
                    f"Aborting. a and a_hash do not match for user {i.name}"
                )

    def __assign_shares(self, data: tuple[NameData, ...], attr):
        """
        We let s_i and e_i be visible from this class. We then create a
        chain where each participant's polynomial gets split into shares
        with their associated name as the "owner" of the share. This then
        gets distributed to all others who are "holders". We then set a
        param in each participant for their array of secret-shares that
        they are holding.
        """
        named_shares = [
            NameData(p.name, self.secret_share.share_poly(p.data)) for p in data
        ]
        temp_dict = dict()
        for share in named_shares:
            for data, name in zip(share.data, self.names):
                temp_dict[name] = temp_dict.get(name, []) + [
                    SecretShareSplit(share.name, name, data)
                ]
        for i in self.participants:
            setattr(i, attr, temp_dict[i.name])

    def DKGen(self):
        self.__assert_a_with_hash()
        self.__recv_share("make_b_i", "h_b")
        self.__assign_shares(self.__recv_data("get_s_i"), "other_s_i")
        self.__assign_shares(self.__recv_data("get_e_i"), "other_e_i")
        self.__recv_data("make_b_bar")


if __name__ == "__main__":
    bgv = BGV()
    bgv.DKGen()
