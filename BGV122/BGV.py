from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.Participant import Participant
from type.classes import NameData, SecretShareSplit


class BGV:
    def __init__(self, n: int = 4, q: int = 2477, N: int = 150):
        self.n = n
        self.q = q
        self.N = N
        self.comm_scheme = CommitmentScheme(q=self.q, N=self.N)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((2, self.n), self.q)
        self.participants: tuple[Participant, ...] = tuple(
            Participant(self.comm_scheme, self.secret_share) for _ in range(n)
        )
        self.names = [i.name for i in self.participants]

    def __recv_value(self, attr):
        try:
            return tuple(i.share_attr(attr) for i in self.participants)
        except Exception as e:
            raise ValueError(
                f"Invalid attribute name in class Participant: {attr}, {e}"
            )

    def __recv_value_shared(self, attr):
        return tuple(
            i.share_others_attr("shares_" + attr) for i in self.participants
        )

    def __share_data(self, attr, data):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name == i.name, data))
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

    def __assign_shares(self, attr: str):
        """
        We let s_i and e_i be visible from this class. We then create a
        chain where each participant's polynomial gets split into shares
        with their associated name as the "owner" of the share. This then
        gets distributed to all others who are "holders". We then set a
        param in each participant for their array of secret-shares that
        they are holding.
        """
        named_shares = [
            NameData(p.name, self.secret_share.share_poly(p.data))
            for p in self.__recv_value(attr)
        ]
        temp_dict = dict()
        for share in named_shares:
            for data, name in zip(share.data, self.names):
                temp_dict[name] = temp_dict.get(name, []) + [
                    SecretShareSplit(share.name, name, data)
                ]
        for i in self.participants:
            i.recv_from_other("shares_" + attr, temp_dict[i.name])

    def reconstruct_shares(self, attr: str):
        """
        Each party sends in their part of the shared secrets, allowing
        us to recreate all of them. Send back the shares corresponding
        to the participant's own 's', they reassure this is correct.
        """
        t = self.__recv_value_shared(attr)
        reconstructed = dict()
        for part in t:
            for p in part.data:
                reconstructed[p.name] = reconstructed.get(p.name, []) + [
                    p.share
                ]
        for i in self.participants:
            if not i.reconstruct(reconstructed[i.name]):
                raise ValueError(
                    f"Aborting. Failed to reconstruct using their shares for participant {i.name}"
                )

    def __broadcast(self):
        """
        Broadcast all com_s, com_e, com_sbar, com_ebar
        """
        for i in self.participants:
            i.bar_vars()
        self.__recv_share("c_s")
        self.__recv_share("c_e")
        self.__recv_share("c_s_bar")
        self.__recv_share("c_e_bar")
        self.__recv_share("b")
        self.__recv_share("b_bar")

        data = self.__recv_value("coms_s_bar")
        self.__share_data("coms_s_bar", data)
        for i in self.participants:
            i.check_open()

    def DKGen(self):
        self.__assert_value_matches_hash("a")
        self.__compute_b()
        self.__assign_shares("s")
        self.__assign_shares("e")
        self.__broadcast()
        self.__assert_value_matches_hash("b")
        self.reconstruct_shares("s")
        self.reconstruct_shares("e")


if __name__ == "__main__":
    bgv = BGV()
    bgv.DKGen()
