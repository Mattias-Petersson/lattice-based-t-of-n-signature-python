from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare import SecretShare
from BGV122.Participant import Participant
from type.classes import NameData


class BGV:
    def __init__(self, n: int = 4, q: int = 2**32 - 527, N: int = 1024):
        self.n = n
        self.q = q
        self.N = N
        self.comm_scheme = CommitmentScheme(q=q, N=N)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.n, self.n), self.q)
        self.participants: tuple[Participant, ...] = tuple(
            Participant(self.comm_scheme) for _ in range(n)
        )

    def __rcv_data(self, fn: str) -> tuple[NameData, ...]:
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

    def __share_data(self, data: tuple[NameData, ...], attr: str):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name != i.name, data))
            try:
                setattr(i, attr, res)
            except Exception as e:
                print(
                    f"Invalid attribute name in class Participant: {attr}, {e}"
                )

    def __recv_share(self, fn, attr):
        self.__share_data(self.__rcv_data(fn), attr)

    def __assert_a_with_hash(self):
        self.__recv_share("a_hash", "hashes")
        self.__recv_share("own_a", "other_a")
        for i in self.__rcv_data("compare_a_hash"):
            if not i.data:
                raise ValueError(
                    f"Aborting. a and a_hash do not match for user {i.name}"
                )

    def DKGen(self):
        self.__assert_a_with_hash()
        self.__recv_share("make_b_i", "h_b")


if __name__ == "__main__":
    bgv = BGV()
    bgv.DKGen()
