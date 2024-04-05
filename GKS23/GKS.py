from BDLOP16.CommitmentScheme import CommitmentScheme
from BGV122.BGV import BGV
from GKS23.GKSParticipant import GKSParticipant
from Models.Controller import Controller
from SecretSharing.SecretShare2 import SecretShare
from type.classes import BGVValues
from utils.Polynomial import Polynomial


class GKS(Controller):
    def __init__(
        self,
        q: int = 2**32 - 527,
        p: int = 2029,
        N: int = 1024,
        t: int = 3,
        n: int = 5,
    ):
        self.q = q
        self.p = p
        self.N = N
        self.t = t
        self.n = n
        self.comm_scheme = CommitmentScheme(q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.N, self.p)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.t, self.n), self.q)
        self.participants: tuple[GKSParticipant, ...] = tuple(
            GKSParticipant(self.comm_scheme, self.secret_share, self.p)
            for _ in range(n)
        )
        bgv_values = BGVValues(
            self.participants,
            self.comm_scheme,
            self.secret_share,
            self.t,
            self.n,
        )
        self.BGV = BGV(bgv_values, p, q, N)

        """self.participants = [
            GKSParticipant(
                self.BGV.comm_scheme, self.BGV.secret_share, self.BGV.p
            )
        ]"""

    def KGen(self):
        print()


if __name__ == "__main__":
    gks = GKS()
    public_keys, secret_keys = gks.BGV.DKGen()
    results = dict()
    for _ in range(100):
        m = gks.BGV.get_message()
        u, v = gks.BGV.enc(m)

        d = gks.BGV.t_dec(secret_keys, u)
        decrypted = gks.BGV.comb(v, d)
        res = decrypted == m
        results[res] = results.get(res, 0) + 1
    print(results)
    print([i.name for i in gks.participants])
