from typing import Iterable
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from GKS23.MultiCounter import MultiCounter
from Models.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.BGVParticipant import BGVParticipant
from type.classes import TN, BGVValues, Ctx, NameData, poly
from Models.Controller import Controller
from utils.Polynomial import Polynomial


class BGV(Controller):
    def __init__(
        self,
        values: BGVValues | None = None,
        p: int = 2029,
        q: int = 2**32 - 527,
        N: int = 1024,
        tn: TN | None = None,
    ):
        self.q = q
        self.N = N
        self.p = p
        self.counter = MultiCounter()
        (
            self.comm_scheme,
            self.secret_share,
            self.participants,
            self.t,
            self.n,
        ) = self.__getValues(values, tn)

        self.polynomial = self.comm_scheme.polynomial
        self.message_space = Polynomial(self.counter, self.N, self.p)
        self.cypari = self.comm_scheme.cypari

        super().__init__(self.participants)

    def __getValues(
        self, values: BGVValues | None, tn: TN | None
    ) -> tuple[
        CommitmentScheme, SecretShare, tuple[BGVParticipant, ...], int, int
    ]:
        if not (values or tn):
            raise ValueError(
                "Requires at least a set of values, or a (t, n) tuple"
            )
        if values:
            return (
                values.comm_scheme,
                values.secret_share,
                values.participants,
                values.t,
                values.n,
            )
        assert tn is not None
        t, n = tn
        comm = BDLOPCommScheme(q=self.q, N=self.N)
        secrets = SecretShare((t, n), self.q)
        part = tuple(
            BGVParticipant(
                comm, secrets, self.counter, self.q, self.p, self.N, i + 1
            )
            for i in range(n)
        )
        return comm, secrets, part, t, n

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

    def __finalize(self):
        for part in self.participants:
            part.generate_final()
        self.__check_equiv("sum_a")
        self.__check_equiv("sum_b")
        return self.participants

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

    def enc(self, u: BGVParticipant, m: poly) -> Ctx:
        return u.enc(m)

    def dec(self, sk, ctx: Ctx):
        return NotImplementedError("Not implemented for this version.")

    def participant_lagrange(self, U: Iterable[BGVParticipant]) -> list[int]:
        return self.secret_share.lagrange([i.x for i in U])

    def t_dec(self, U: Iterable[BGVParticipant], ctx: Ctx):
        x_list = self.participant_lagrange(U)
        d = [part.t_dec(ctx, x) for part, x in zip(U, x_list)]
        return d

    def comb(self, u: BGVParticipant, ctx: Ctx, d: list):
        return u.comb(ctx, d)

    def get_message(self):
        return self.message_space.uniform_element()


if __name__ == "__main__":
    bgv = BGV(tn=(3, 5))
    participants = bgv.DKGen()
    part = next(iter(participants))
    results = dict()
    for _ in range(100):
        m = bgv.get_message()
        ctx = bgv.enc(part, m)
        d = bgv.t_dec(participants, ctx)
        decrypted = bgv.comb(part, ctx, d)
        decrypted2 = part.comb(ctx, d)
        res = decrypted == m
        results[res] = results.get(res, 0) + 1
    print(results)
