from typing import Iterable
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from BGV122.BGV import BGV
from GKS23.GKSParticipant import GKSParticipant
from GKS23.MultiCounter import MultiCounter
from Models.Controller import Controller
from Models.values import default_values
from SecretSharing.SecretShare2 import SecretShare
from type.classes import BGVValues, Signature, poly
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
        self.comm_scheme = BDLOPCommScheme(q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.N, self.p)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.t, self.n), self.q)
        self.counter = MultiCounter()
        self.participants: tuple[GKSParticipant, ...] = tuple(
            GKSParticipant(
                self.comm_scheme,
                self.secret_share,
                self.message_space,
                self.counter,
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
        self.BGV.DKGen()
        super().__init__(self.participants)

    def __get_from_subset(self, attr, U: Iterable[GKSParticipant]):
        return [i.share_attr(attr) for i in U]

    def __send_to_subset(self, attr, U: Iterable[GKSParticipant]):
        data = self.__get_from_subset(attr, U)
        for i in U:
            i.recv_from_subset(attr, data)

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

    def __sign_1(self, mu: poly, U: Iterable[GKSParticipant]):
        for p in U:
            p.sign_1(mu)
        self.__send_to_subset("ctx_r", U)
        self.__send_to_subset("w", U)

    def __sign_2(self, mu: poly, U: Iterable[GKSParticipant], lagrange_x):
        for p, x in zip(U, lagrange_x):
            p.sign_2(mu, x)
        self.__send_to_subset("ds", U)
        self.__send_to_subset("com_w", U)

    def sign(self, mu: poly, U: Iterable[GKSParticipant]) -> list[Signature]:
        lagrange_x = self.BGV.participant_lagrange(U)
        self.__sign_1(mu, U)
        self.__sign_2(mu, U, lagrange_x)
        return [p.generate_signature() for p in U]

    def vrfy(self, mu, u: GKSParticipant, signature: Signature):
        return u.verify_signature(mu, signature)


if __name__ == "__main__":
    gks = GKS(**default_values)
    results = dict()
    participants = gks.KGen()
    m_sign = gks.BGV.get_message()
    part = participants[0]
    signatures = gks.sign(m_sign, participants[:2])
    print(gks.vrfy(m_sign, participants[0], signatures[0]))
    print(gks.counter.q_mult)
