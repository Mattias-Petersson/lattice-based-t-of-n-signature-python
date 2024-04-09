from BDLOP16.CommitmentScheme import CommitmentScheme
from BGV122.BGVParticipant import BGVParticipant
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, Ctx, NameData


class GKSParticipant(BGVParticipant):
    def __init__(
        self,
        comm_scheme: CommitmentScheme,
        secret_share: SecretShare,
        q: int,
        p: int,
        N: int,
        x: int,
    ):
        super().__init__(comm_scheme, secret_share, q, p, N, x)
        self.a = self.polynomial.uniform_element()
        self.a_hash = self.hash(self.a)

    def __cross_prod(self, vec_1, vec_2):
        return sum([v1 * v2 for v1, v2 in zip(vec_1, vec_2, strict=True)])

    def __add_ctx(self, name):
        ctx_name = "ctx_" + name
        own: list[Ctx] = getattr(self, ctx_name)
        others: list[NameData] = self.others[ctx_name]
        all_ctx = [Ctx(own[0].u, own[0].v), Ctx(own[1].u, own[1].v)]
        for d in others:
            ctx = d.data
            all_ctx[0] += ctx[0]
            all_ctx[1] += ctx[1]
        return all_ctx

    def KGen_step_2(self):
        self.sum_a = self.a + sum([i.data for i in self.others["a"]])
        self.a_vector = [self.sum_a, 1]

    def KGen_step_3(self):
        self.s = self.gaussian(2)
        self.y = self.__cross_prod(self.a_vector, self.s)
        self.y_hash = self.hash(self.y)
        self.ctx_s = [self.enc(s) for s in self.s]

    def KGen_step_4(self):
        self.sum_y = self.y + sum([i.data for i in self.others["y"]])
        self.sum_ctx_s = self.__add_ctx("s")
        self.pk = (self.a_vector, self.sum_y)
