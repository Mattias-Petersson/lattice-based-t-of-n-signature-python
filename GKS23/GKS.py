from typing import Iterable
from BDLOP16.CommitmentScheme import CommitmentScheme
from BGV122.BGV import BGV
from GKS23.GKSParticipant import GKSParticipant
from Models.Controller import Controller
from Models.values import default_values
from SecretSharing.SecretShare2 import SecretShare
from type.classes import BGVValues, Sk, poly
from utils.Polynomial import Polynomial


class GKS(Controller):
    def __init__(
        self,
        q: int,
        p: int,
        N: int,
        t: int,
        n: int,
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
            GKSParticipant(
                self.comm_scheme,
                self.secret_share,
                self.q,
                self.p,
                self.N,
                i + 1,
            )
            for i in range(n)
        )
        bgv_values = BGVValues(
            self.participants,
            self.comm_scheme,
            self.secret_share,
            self.t,
            self.n,
        )
        self.BGV = BGV(bgv_values, p, q, N)
        super().__init__(self.participants)

    def __KGen_step_2(self):
        self.assert_value_matches_hash("a")
        for p in self.participants:
            p.KGen_step_2()

    def __KGen_step_3(self):
        for p in self.participants:
            p.KGen_step_3()
        self.recv_share("y")
        self.recv_share("ctx_s")

    def __finalize(self):
        self.assert_value_matches_hash("y")
        for part in self.participants:
            part.KGen_step_4()
        return self.participants

    def KGen(self):
        """
        KGen of actively secure GKS23. Step one is init BGV, which is done in
        the constructor and is thus not included here.
        """
        self.__KGen_step_2()
        self.__KGen_step_3()
        return self.__finalize()


if __name__ == "__main__":
    gks = GKS(**default_values)
    bgv_participants = gks.BGV.DKGen()
    part = next(iter(bgv_participants))
    results = dict()
    participants = gks.KGen()
    for _ in range(100):
        m = gks.BGV.get_message()
        ctx = part.enc(m)
        d = gks.BGV.t_dec(bgv_participants[: gks.BGV.t], ctx)
        decrypted = part.comb(ctx, d)
        res = decrypted == m
        results[res] = results.get(res, 0) + 1
    print(results)
