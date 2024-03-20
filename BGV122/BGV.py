from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.Participant import Participant
from type.classes import NameData, SecretShareSplit


class BGV:
    def __init__(self, t: int = 2, n: int = 4, q: int = 2477, N: int = 150):
        self.t = t
        self.n = n
        self.q = q
        self.N = N
        self.comm_scheme = CommitmentScheme(q=self.q, N=self.N)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.t, self.n), self.q)
        self.participants: tuple[Participant, ...] = tuple(
            Participant(self.comm_scheme, self.secret_share) for _ in range(n)
        )
        self.names = [i.name for i in self.participants]

    def __recv_value(self, attr):
        try:
            return [i.share_attr(attr) for i in self.participants]
        except Exception as e:
            raise ValueError(
                f"Invalid attribute name in class Participant: {attr}, {e}"
            )

    def __recv_value_shared(self, attr):
        return tuple(i.share_others_attr(attr) for i in self.participants)

    def __share_data(self, attr, data):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name != i.name, data))
            i.recv_from_other(attr, res)

    def __recv_share(self, attr_name: str):
        return self.__share_data(attr_name, self.__recv_value(attr_name))

    def __assert_value_matches_hash(self, attr):
        """
        Takes in the hash of an attr all participants, then all values. Then each
        participant does a check if the hashes they received correspond to the
        value they received when hashed.
        """
        self.__recv_share(attr + "_hash")
        self.__recv_share(attr)
        for i in self.participants:
            if not i.compare_hash(attr).data:
                raise ValueError(
                    f"Aborting. {attr} and {attr}_hash do not match for user {i.name}"
                )

    def __compute_b(self):
        """
        Computes b for all participants, shares a hash of b with the others.
        """
        for i in self.participants:
            i.make_b()
        self.__recv_share("b_hash")

    def __share_b_bar(self):
        for i in self.participants:
            i.make_secrets()
        data = self.__recv_value("b_bar")
        shares = dict()
        for i in data:
            for j, name in zip(i.data, self.names):
                shares[name] = shares.get(name, []) + [NameData(i.name, j)]
        for part in self.participants:
            part.recv_from_other("b_bar", shares[part.name])

    def __share_s_bar(self):
        data = self.__recv_value("coms_s_bar")
        shares = dict()
        for i in data:
            for j, name in zip(i.data, self.names):
                shares[name] = shares.get(name, []) + [NameData(i.name, j)]
        for part in self.participants:
            part.recv_from_other("s_bar", shares[part.name])

    def __broadcast(self):
        self.__recv_share("c_s")
        self.__recv_share("c_e")
        self.__recv_share("c_s_bar")
        self.__recv_share("c_e_bar")
        self.__recv_share("b")

    def __recreate(self):
        data = self.__recv_value_shared("b_bar")
        recreated = dict()
        for i in data:
            for j in i.data:
                recreated[j.name] = recreated.get(j.name, []) + [
                    NameData(i.name, j.data)
                ]
        for i in self.participants:
            i.reconstruct(recreated[i.name], self.t)

    def DKGen(self):
        """
        Key generation method, if any of the methods return false they will
        throw an error. If all succeed we return a public key and a secret key
        for each participant.

        """
        self.__assert_value_matches_hash("a")
        self.__compute_b()
        self.__share_b_bar()
        self.__broadcast()
        self.__assert_value_matches_hash("b")
        self.__recreate()
        self.__share_s_bar()


if __name__ == "__main__":
    bgv = BGV()
    bgv.DKGen()
