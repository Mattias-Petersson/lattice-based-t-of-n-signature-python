from BDLOP16.CommitmentScheme import CommitmentScheme
from BGV122.BGVParticipant import BGVParticipant
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, Ctx, GksPk, Signature, poly


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
        self.from_u = dict()

        self.a = self.polynomial.uniform_element()
        self.a_hash = self.hash(self.a)

    def recv_from_subset(self, attr: str, data):
        self.from_u[attr] = data

    def __cross_prod(self, vec_1, vec_2):
        return sum([v1 * v2 for v1, v2 in zip(vec_1, vec_2, strict=True)])

    def __sum_ctx_s(self) -> list[Ctx]:
        own = self.ctx_s
        ctx1 = Ctx(own[0].u, own[0].v)
        ctx2 = Ctx(own[1].u, own[1].v)
        for d in self.others["ctx_s"]:
            ctx1 += d.data[0]
            ctx2 += d.data[1]
        return [ctx1, ctx2]

    def __sum_ctx_r(self) -> list[Ctx]:
        ctx1, ctx2 = Ctx(0, 0), Ctx(0, 0)
        for d in self.from_u["ctx_r"]:
            ctx1 += d.data[0]
            ctx2 += d.data[1]
        return [ctx1, ctx2]

    def KGen_step_2(self):
        sum_a = self.a + sum([i.data for i in self.others["a"]])
        self.a_vector = [sum_a, 1]

    def KGen_step_3(self):
        self.s = self.gaussian(2)
        self.y = self.__cross_prod(self.a_vector, self.s)
        self.y_hash = self.hash(self.y)
        self.ctx_s = [self.enc(s) for s in self.s]

    def KGen_step_4(self):
        sum_y = self.y + sum([i.data for i in self.others["y"]])
        self.sum_ctx_s: list[Ctx] = self.__sum_ctx_s()
        self.pk: GksPk = GksPk(self.a_vector, sum_y)

    def sign_1(self, mu):
        r = self.gaussian(2)
        ck = self.hash((self.pk, mu))
        self.w = self.__cross_prod(self.a_vector, r)
        self.com_w = Commit(self.w, self.comm_scheme.r_commit())
        [self.c_w] = self.comm_scheme.commit(self.com_w)
        self.ctx_r = [self.enc(i) for i in r]

    def sign_2(self, mu, x: int):
        self.c: poly = self.hash((self.w, self.pk, mu))
        c_ctx: list[Ctx] = [ci * self.c for ci in self.ctx_s]
        sum_ctx_r = self.__sum_ctx_r()
        self.ctx_z: list[Ctx] = [
            c + r for c, r in zip(c_ctx, sum_ctx_r, strict=True)
        ]
        self.ds = [self.t_dec(z, x) for z in self.ctx_z]

    def generate_signature(self) -> Signature:
        d0 = []
        d1 = []
        for d in self.from_u["ds"]:
            d0.append(d.data[0])
            d1.append(d.data[1])
        z = [
            self.comb(z, dd) for z, dd in zip(self.ctx_z, [d0, d1], strict=True)
        ]
        rho = sum([com.data.r for com in self.from_u["com_w"]])
        return Signature(self.c, z, rho)

    def verify_signature(self, mu, signature: Signature):

        az = self.__cross_prod(self.a_vector, signature.z)
        cy = signature.c * self.pk[1]

        az_in_rq = (
            self.cypari.liftall(az)
            * self.cypari.Mod(1, self.q)
            * self.cypari.Mod(1, self.polynomial.basis_poly())
        )
