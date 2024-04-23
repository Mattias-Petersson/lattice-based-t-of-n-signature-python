from typing import Iterable
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from BGV122.BGV import BGV
from GKS23.GKSParticipant import GKSParticipant
from Models.Controller import Controller
from utils.values import default_values
from SecretSharing.SecretShare2 import SecretShare
from type.classes import TN, BGVValues, Signature, poly
from utils.Polynomial import Polynomial


class GKS(Controller):
    def __init__(
        self,
        Q: int,
        q: int,
        p: int,
        N: int,
        tn: TN,
    ):
        self.Q = Q
        self.q = q
        self.p = p
        self.N = N
        self.t, self.n = tn
        self.comm_scheme = BDLOPCommScheme(q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.p, self.N)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare(tn, self.p)

        self.BGV_comm_scheme = BDLOPCommScheme(q=self.Q, N=self.N)
        self.BGV_secret_share = SecretShare(tn, self.Q)

        self.participants: tuple[GKSParticipant, ...] = tuple(
            GKSParticipant(
                self.comm_scheme,
                self.BGV_comm_scheme,
                self.BGV_secret_share,
                self.Q,
                self.q,
                self.p,
                self.N,
                i + 1,
            )
            for i in range(self.n)
        )
        bgv_values = BGVValues(
            self.participants, self.BGV_comm_scheme, self.BGV_secret_share, tn
        )
        self.BGV = BGV(bgv_values, q, Q, N)
        self.BGV.DKGen()
        super().__init__(self.participants)

    def __get_from_subset(self, attr, U: Iterable[GKSParticipant]):
        return [i.share_attr(attr) for i in U]

    def __send_to_subset(self, attr, U: Iterable[GKSParticipant]):
        data = self.__get_from_subset(attr, U)
        for i in U:
            i.recv_from_subset(attr, data)

    def __KGen_step_2(self):
        self.assert_value_matches_hash("a_ts")
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

    def get_message(self):
        return self.message_space.uniform_element()


if __name__ == "__main__":
    gks = GKS(**default_values)
    results = dict()
    participants = gks.KGen()
    for _ in range(10):
        m_sign = gks.get_message()
        m_enc = gks.BGV.get_message()
        part = participants[0]
        signatures = gks.sign(m_sign, participants[:2])
        ctx = participants[0].enc(m_enc)
        t_dec = gks.BGV.t_dec(participants[:2], ctx)
        m_star = part.comb(ctx, t_dec)
        res = gks.vrfy(m_sign, part, signatures[0])
        results[res] = results.get(res, 0) + 1

    print(results)
