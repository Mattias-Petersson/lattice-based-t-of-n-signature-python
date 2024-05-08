import time
from typing import Iterable
from BDLOP16.BDLOP import BDLOP
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from BDLOP16.RelationProver import RelationProver
from BGV12.BGV import BGV
from GKS23.GKSParticipant import GKSParticipant
from GKS23.MultiCounter import MultiCounter
from Models.Controller import Controller
from utils.values import default_values, Q
from utils.Polynomial import Polynomial
from SecretSharing.SecretShare import SecretShare
from type.classes import TN, BGVValues, Signature, poly


class GKS(
    Controller
):  # TODO: MAKE A GKS CONTROLLER FOR REVISED (branch or something)
    def __init__(
        self,
        Q: int,
        q: int,
        p: int,
        N: int,
        tn: TN,
        revised: bool,
    ):
        self.revised = revised
        self.Q = Q
        self.q = q
        self.p = p
        self.N = N
        self.counter = MultiCounter()
        self.t, self.n = tn
        self.comm_scheme = BDLOPCommScheme(self.counter, q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.counter, self.p, self.N)
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare(tn, self.p, self.counter)

        self.BGV_comm_scheme = BDLOPCommScheme(self.counter, q=self.Q, N=self.N)
        self.BGV_secret_share = SecretShare(tn, self.Q, self.counter)
        self.RP = RelationProver(
            BDLOP(self.comm_scheme),
            self.comm_scheme,
            self.secret_share,
        )
        self.BGV_RP = RelationProver(
            BDLOP(self.BGV_comm_scheme),
            self.BGV_comm_scheme,
            self.BGV_secret_share,
        )
        a_ts = None
        sum_a = None
        self.revised = revised
        if revised:
            a_ts = self.comm_scheme.polynomial.uniform_element()
            sum_a = self.BGV_comm_scheme.polynomial.uniform_element()

        self.participants: tuple[GKSParticipant, ...] = tuple(
            GKSParticipant(
                self.comm_scheme,
                self.BGV_comm_scheme,
                self.BGV_secret_share,
                self.RP,
                self.BGV_RP,
                self.counter,
                self.Q,
                self.q,
                self.p,
                self.N,
                i + 1,
                a_ts,
                sum_a,
            )
            for i in range(self.n)
        )
        bgv_values = BGVValues(
            self.participants, self.BGV_comm_scheme, self.BGV_secret_share, tn
        )
        self.BGV = BGV(self.counter, q, Q, N, self.revised, values=bgv_values)
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
        self.recv_share("proof_s")

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
        if not self.revised:
            self.__KGen_step_2()
        self.__KGen_step_3()
        return self.__finalize()

    def __sign_1(self, U: Iterable[GKSParticipant]):
        for p in U:
            p.sign_1()
        self.__send_to_subset("ctx_r", U)
        self.__send_to_subset("proof_r", U)
        self.__send_to_subset("w", U)
        self.__send_to_subset("c_w", U)

    def __sign_2(self, mu: poly, U: Iterable[GKSParticipant], lagrange_x):
        for p, x in zip(U, lagrange_x):
            p.sign_2(mu, x)
        self.__send_to_subset("ds", U)
        self.__send_to_subset("com_w", U)

    def sign(self, mu: poly, U: Iterable[GKSParticipant]) -> list[Signature]:
        lagrange_x = self.BGV.participant_lagrange(U)
        self.__sign_1(U)
        self.__sign_2(mu, U, lagrange_x)
        return [p.generate_signature() for p in U]

    def vrfy(self, mu, u: GKSParticipant, signature: Signature):
        return u.verify_signature(mu, signature)

    def get_message(self):
        return self.message_space.uniform_element()


if __name__ == "__main__":
    now = time.time()
    gks = GKS(Q, revised=False, **default_values)
    results = dict()
    participants = gks.KGen()
    gks.counter.print()
    gks.counter.reset()
    print(round(time.time() - now, 6), "seconds")
    now = time.time()
    for _ in range(1):
        m_sign = gks.get_message()
        part = participants[0]
        signatures = gks.sign(m_sign, participants[: gks.t])
        res = gks.vrfy(m_sign, part, signatures[0])
        results[res] = results.get(res, 0) + 1
        gks.counter.print()
        gks.counter.reset()
    print(round(time.time() - now, 6), "seconds")
    print(results)
