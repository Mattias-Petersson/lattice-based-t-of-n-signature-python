import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.BGVParticipant import BGVParticipant
from type.classes import NameData, Sk, poly
from Controller.Controller import Controller
from utils.Polynomial import Polynomial


class BGV(Controller):
    def __init__(
        self,
        t: int = 3,
        n: int = 5,
        p: int = 2029,
        q: int = 2**32 - 527,
        N: int = 1024,
    ):
        self.t = t
        self.n = n
        self.q = q
        self.N = N
        self.p = p
        self.comm_scheme = CommitmentScheme(q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.N, self.p)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.t, self.n), self.q)
        self.participants: tuple[BGVParticipant, ...] = tuple(
            BGVParticipant(self.comm_scheme, self.secret_share, self.p)
            for _ in range(n)
        )
        super().__init__(self.participants)

    def __compute_b(self):
        """
        Computes b for all participants, shares a hash of b with the others.
        """
        for i in self.participants:
            i.make_b()
        self.recv_share("b_hash")

    def __share_b_bar(self):
        for i in self.participants:
            i.make_secrets()
        self.share_partials("b_bar")

    def __share_commits(self):
        """
        Shares the c which is the result of committing a Commit object between
        all participants. Also shares said object for s_bar between all users.
        Each participant then looks at their received values and checks if
        all of them open successfully.
        """
        self.share_partials("coms_s_bar")
        self.share_partials("c_s_bar")
        self.share_partials("c_e_bar")
        for part in self.participants:
            part.check_open()

    def __broadcast(self):
        """
        Broadcasts user-specific values between all participants.
        """
        self.recv_share("c_s")
        self.recv_share("c_e")
        self.recv_share("b")

    def __recreate(self):
        """
        Asserts that for all users, their b can be reconstructed from b_bars.
        All combinations are tested for by each participant.
        """
        data = self.recv_value_shared("b_bar")
        recreated = dict()
        for i in data:
            for j in i.data:
                recreated[j.name] = recreated.get(j.name, []) + [
                    NameData(i.name, j.data)
                ]
        for i in self.participants:
            i.reconstruct(recreated[i.name], self.t)

    def __check_equiv(self, attr) -> poly:
        all_attr = [getattr(i, attr) for i in self.participants]
        if len(set(all_attr)) != 1:
            raise ValueError(f"Users did not get matching values for {attr}")
        return all_attr.pop()

    def __finalize(self) -> tuple[list, list[Sk]]:
        keys = dict()
        for idx, part in enumerate(self.participants):
            pk, sk = part.generate_final()
            keys["sk"] = keys.get("sk", []) + [Sk(part.name, idx + 1, sk)]
            keys["pk"] = keys.get("pk", []) + [pk]

        self.a = self.__check_equiv("sum_a")
        self.b = self.__check_equiv("sum_b")
        return keys["pk"], keys["sk"]

    def DKGen(self):
        """
        Key generation method, if any of the methods return false they will
        throw an error. If all succeed we return a public key and a secret key
        for each participant.
        """
        self.assert_value_matches_hash("a")
        self.__compute_b()
        self.__share_b_bar()
        self.__broadcast()
        self.assert_value_matches_hash("b")
        self.__recreate()
        self.__share_commits()
        return self.__finalize()

    def enc(self, m: poly) -> tuple[poly, poly]:
        r, e_prime, e_bis = [
            self.polynomial.gaussian_element(1) for _ in range(3)
        ]
        mprime = self.cypari.liftall(m)
        u = self.a * r + self.p * e_prime
        v = self.b * r + self.p * e_bis + mprime
        return u, v

    def dec(self, sk, u):
        return NotImplementedError("Not implemented for this version.")

    def t_dec(self, sk: list[Sk], u):
        lagrange = self.secret_share.lagrange([i.x for i in sk])
        M = [coeff * com.commit.m * u for coeff, com in zip(lagrange, sk)]
        E = [self.polynomial.uniform_element(2) for _ in sk]
        d = [m + self.p * e for m, e in zip(M, E)]
        return d

    def comb(self, v: poly, d: list):
        round_and_pol = lambda x: self.cypari.Pol(self.cypari.round(x))
        q_half = (self.q - 1) / 2
        q_half_p = q_half % self.p
        helper_array = round_and_pol(np.ones(self.N) * q_half)
        ptx = self.cypari.liftall(v - sum(d) + helper_array) * self.cypari.Mod(
            1, self.p
        )
        ptx -= round_and_pol(np.ones(self.N) * (q_half_p))
        return ptx

    def get_message(self):
        return self.message_space.uniform_element()


if __name__ == "__main__":
    bgv = BGV()
    public_keys, secret_keys = bgv.DKGen()
    results = dict()
    for _ in range(100):
        m = bgv.get_message()
        u, v = bgv.enc(m)

        d = bgv.t_dec(secret_keys, u)
        decrypted = bgv.comb(v, d)
        res = decrypted == m
        results[res] = results.get(res, 0) + 1
    print(results)
