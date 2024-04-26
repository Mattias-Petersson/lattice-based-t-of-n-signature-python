from BDLOP16.RelationProofs import RelationProver
from BGV122.BGVParticipant import BGVParticipant
from Models.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from type.classes import Commit, Ctx, GksPk, Signature, poly


class GKSParticipant(BGVParticipant):
    def __init__(
        self,
        comm_scheme: CommitmentScheme,
        BGV_comm_scheme: CommitmentScheme,
        secret_share: SecretShare,
        relation_prover: RelationProver,
        BGV_relation_prover: RelationProver,
        Q: int,
        q: int,
        p: int,
        N: int,
        x: int,
    ):
        super().__init__(
            BGV_comm_scheme,
            secret_share,
            relation_prover,
            BGV_relation_prover,
            Q,
            q,
            p,
            N,
            x,
        )
        self.comm_scheme = comm_scheme
        self.from_u = dict()
        self.polynomial = comm_scheme.polynomial
        self.a_ts = self.polynomial.uniform_element()
        self.a_ts_hash = self.hash(self.a_ts)

    def hash(self, m):
        return self.polynomial.hash(self.comm_scheme.kappa, m)

    def recv_from_subset(self, attr: str, data):
        self.from_u[attr] = data

    def __verify_ctx(self, d):
        if not (
            d.data[0].verify(
                self.BGV_relation_prover, self.sum_a, self.sum_b, self.q
            )
        ) and d.data[1].verify(
            self.BGV_relation_prover, self.sum_a, self.sum_b, self.q
        ):
            raise ValueError(
                f"Aborting. User {self.name} got an failing enc_proof for "
                + f"user {d.name}"
            )

    def __cross_prod(self, vec_1, vec_2):
        return sum(v1 * v2 for v1, v2 in zip(vec_1, vec_2, strict=True))

    def __make_ctx_s(self) -> list[Ctx]:
        """
        Ctx_s is the sum of all individual ciphertexts ctx_s_j.
        """
        ctx0 = Ctx(0, 0, None)
        ctx1 = Ctx(0, 0, None)
        for d in self.others["ctx_s"]:
            self.__verify_ctx(d)
            ctx0 += d.data[0]
            ctx1 += d.data[1]
        return [ctx0, ctx1]

    def __sum_ctx_r(self) -> list[Ctx]:
        ctx1, ctx2 = Ctx(0, 0, None), Ctx(0, 0, None)
        for d in self.from_u["ctx_r"]:
            self.__verify_ctx(d)
            ctx1 += d.data[0]
            ctx2 += d.data[1]
        return [ctx1, ctx2]

    def KGen_step_2(self):
        sum_a = sum(i.data for i in self.others["a_ts"])
        self.a_vector = [sum_a, 1]

    def KGen_step_3(self):
        self.s = self.polynomial.gaussian_array(2, 4)
        self.y = self.__cross_prod(self.a_vector, self.s)
        self.y_hash = self.hash(self.y)
        self.proof_s = self.relation_prover.prove_s(self.a_vector, self.s)
        self.ctx_s = [self.enc(s) for s in self.s]

    def KGen_step_4(self):
        for proof, y in zip(self.others["proof_s"], self.others["y"]):
            if not self.relation_prover.verify_s(
                *proof.data, self.a_vector, y.data
            ):
                raise ValueError(
                    f"Aborting. User {self.name} got an failing r_proof for "
                    + f"user {proof.name}"
                )
        sum_y = sum(i.data for i in self.others["y"])
        self.sum_ctx_s: list[Ctx] = self.__make_ctx_s()
        self.pk: GksPk = GksPk(self.a_vector, sum_y)

    def sign_1(self, mu):
        r = self.polynomial.gaussian_array(2, 2**13)
        ck = self.hash((self.pk, mu))
        self.w = self.__cross_prod(self.a_vector, r)
        self.com_w = Commit(self.w, self.comm_scheme.r_commit())
        self.c_w = self.comm_scheme.commit(self.com_w)
        self.proof_r = self.relation_prover.prove_r(
            self.a_vector, r, self.com_w.r
        )
        self.ctx_r = [self.enc(i) for i in r]

    def sign_2(self, mu, x: int):
        for proof, c_w in zip(self.from_u["proof_r"], self.from_u["c_w"]):
            if not self.relation_prover.verify_r(
                *proof.data, self.a_vector, c_w.data
            ):
                raise ValueError(
                    f"Aborting. User {self.name} got an failing r_proof for "
                    + f"user {proof.name}"
                )
        self.sum_cw = self.cypari.liftall(
            sum(u.data for u in self.from_u["c_w"])
        )
        self.c: poly = self.hash((self.sum_cw, self.pk, mu))
        c_ctx: list[Ctx] = [ci * self.c for ci in self.sum_ctx_s]
        sum_ctx_r = self.__sum_ctx_r()
        self.ctx_z: list[Ctx] = [
            c + r for c, r in zip(c_ctx, sum_ctx_r, strict=True)
        ]
        self.ds = [self.t_dec(z, x) for z in self.ctx_z]

    def generate_signature(self) -> Signature:
        d0, d1 = [], []
        for d in self.from_u["ds"]:
            d0.append(d.data[0])
            d1.append(d.data[1])

        z = [self.comb(z, d) for z, d in zip(self.ctx_z, [d0, d1], strict=True)]
        rho = sum(com.data.r for com in self.from_u["com_w"])
        return Signature(self.c, z, rho)

    def verify_signature(self, mu, signature: Signature):
        az = self.__cross_prod(self.a_vector, signature.z)
        cy = signature.c * self.pk.y
        w_star = self.cypari.liftall(az - cy)
        hashed = self.hash(
            (
                self.cypari.liftall(
                    self.comm_scheme.commit(Commit(w_star, signature.rho))
                ),
                self.pk,
                mu,
            )
        )
        return hashed == self.c
