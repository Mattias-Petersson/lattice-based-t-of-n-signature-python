import itertools
import numpy as np
from BDLOP16.RelationProver import RelationProver
from GKS23.MultiCounter import MultiCounter
from Models.CommitmentScheme import CommitmentScheme
from Models.Participant import Participant
from SecretSharing.SecretShare import SecretShare
from type.classes import Commit, CommitOpen, Ctx, BgvPk, SecretSharePoly, BgvSk


class BGVParticipant(Participant):
    def __init__(
        self,
        comm_scheme: CommitmentScheme,
        secret_share: SecretShare,
        BGV_relation_prover: RelationProver,
        counter: MultiCounter,
        Q: int,
        q: int,
        p: int,
        N: int,
        x: int,
    ):
        super().__init__(secret_share, counter, Q, q, p, N, x)
        self.Q = Q
        self.q = q
        self.BGV_comm_scheme = comm_scheme
        self.BGV_polynomial = self.BGV_comm_scheme.polynomial
        self.BGV_relation_prover = BGV_relation_prover
        self.counter = counter
        self.BGV_hash = lambda x: self.BGV_polynomial.hash(
            self.BGV_comm_scheme.kappa, x
        )
        # 39 chosen to match Dilithium specs for number of +/- 1 in challenge.
        self.kappa = 39
        self.ternary = lambda: self.BGV_polynomial.challenge(self.kappa)
        self.a = self.BGV_polynomial.uniform_element()
        self.cypari = self.BGV_polynomial.cypari
        self.a_hash = self.BGV_hash(self.a)

    def hash(self, x):
        return self.BGV_hash(x)

    def make_b(self):
        self.sum_a = sum(i.data for i in self.others["a"])
        self.s, self.e = self.ternary(), self.ternary()

        self.com_s = self.__commit(self.s)
        self.c_s = self.BGV_comm_scheme.commit(self.com_s)

        self.com_e = self.__commit(self.e)
        self.c_e = self.BGV_comm_scheme.commit(self.com_e)
        self.counter.inc_add()
        self.counter.inc_mult(2)
        self.b = self.sum_a * self.s + self.q * self.e
        self.b_hash = self.BGV_hash(self.b)

    def __commit(self, commitment):
        """
        Returns a commit object of the commitment and a randomness r. Can
        be used to commit with a commitment scheme and return c.
        """
        return Commit(commitment, self.BGV_comm_scheme.r_commit())

    def make_secrets(self):
        def to_tuple(attr):
            return tuple(vals[attr])

        def add_val(name, val):
            return vals.get(name, []) + [val]

        def make_b(s, e):
            if s.x != e.x:
                raise ValueError()
            self.counter.inc_add()
            self.counter.inc_mult(2)
            return SecretSharePoly(s.x, self.sum_a * s.p + self.q * e.p)

        self.s_bar = self.secret_share.share_poly(self.s)
        self.e_bar = self.secret_share.share_poly(self.e)
        vals = dict()
        c_s_bars = []
        c_e_bars = []
        s_rs = []
        e_rs = []
        for s, e in zip(self.s_bar, self.e_bar):
            vals["b_bar"] = add_val("b_bar", make_b(s, e))
            com_s_bar = self.__commit(s.p)
            vals["coms_s_bar"] = add_val("coms_s_bar", com_s_bar)
            c_s_bars.append(self.BGV_comm_scheme.commit(com_s_bar))
            com_e_bar = self.__commit(e.p)
            c_e_bars.append(self.BGV_comm_scheme.commit(com_e_bar))
            s_rs.append(com_s_bar.r)
            e_rs.append(com_e_bar.r)

        self.sk_proof = self.BGV_relation_prover.prove_sk(
            self.com_s.r,
            self.com_e.r,
            s_rs,
            e_rs,
            self.sum_a,
            self.q,
        )
        self.b_bar = to_tuple(
            "b_bar"
        )  # only shares partially, each part to who should get it
        self.b_bars = to_tuple("b_bar")  # shares all parts to everyone
        self.coms_s_bar = to_tuple("coms_s_bar")
        self.c_s_bar = c_s_bars
        self.c_e_bar = c_e_bars

    def reconstruct(self, data, t):
        """
        Attempts to reconstruct this participant's own b, using the shares
        provided to them from the BGV class in the data param. All possible
        combinations are tried, as all should return true. If any combination
        returns false we print out the user for which the process failed, and
        which key shares were responsible.
        """
        combs = list(itertools.combinations(data, t))
        for c in combs:
            pol = self.secret_share.reconstruct_poly([i.data for i in c])
            if pol != self.b:
                raise ValueError(
                    f"Aborting. Reconstructing b failed for user {self.name}"
                    + f", reconstructing polynomials for users: {[i.name for i in c]}",
                )

    def check_open(self):
        for cs, ce, cs_bar, ce_bar, com, b, b_bar, proofs in zip(
            self.others["c_s"],
            self.others["c_e"],
            self.others["c_s_bar"],
            self.others["c_e_bar"],
            self.others["coms_s_bar"],
            self.others["b"],
            self.others["b_bars"],
            self.others["sk_proof"],
        ):
            if cs_bar.name != com.name:
                raise ValueError(
                    "Aborting. Name mismatch for participants."
                    + f"{self.name}: {cs_bar.name, com.name}"
                )

            if not self.BGV_comm_scheme.open(
                CommitOpen(cs_bar.data[self.x - 1], com.data)
            ):
                raise ValueError(
                    f"Aborting. User {self.name} got an invalid opening for "
                    + f"user {cs_bar.name}"
                )
            for indices in list(
                itertools.combinations(
                    range(self.secret_share.n), self.secret_share.t
                )
            ):
                if (
                    self.secret_share.reconstruct_poly(
                        [b_bar.data[i] for i in indices]
                    )
                    != b.data
                ):
                    raise ValueError(
                        f"Aborting. User {self.name} got an invalid sk proof for "
                        + f"user {cs_bar.name} for indicies {indices}"
                    )
            self.BGV_relation_prover.verify_sk(
                b.data,
                b_bar.data,
                self.sum_a,
                self.q,
                cs.data,
                ce.data,
                cs_bar.data,
                ce_bar.data,
                *proofs.data,
            )

    def generate_final(self):
        self.sum_b = sum(i.data for i in self.others["b"])
        new_com = 0
        new_r = 0
        for com in self.others["coms_s_bar"]:
            self.counter.inc_add(2)
            new_com += com.data.m
            new_r += com.data.r
        self.c_s_k = [
            sum(i.data[j] for i in self.others["c_s_bar"])
            for j in range(self.secret_share.n)
        ]
        self.pk = BgvPk(self.sum_a, self.sum_b, self.c_s_k)
        self.sk = BgvSk(self.x, Commit(new_com, new_r))
        return self.pk, self.sk

    def enc(self, m) -> Ctx:
        r, e_prime, e_bis = self.BGV_polynomial.gaussian_array(3, 1)
        mprime = self.cypari.liftall(m)
        self.counter.inc_add(3)
        self.counter.inc_mult(4)
        u = self.sum_a * r + self.q * e_prime
        v = self.sum_b * r + self.q * e_bis + mprime
        proof = self.BGV_relation_prover.prove_enc(
            r,
            self.BGV_polynomial.in_rq(mprime),
            e_prime,
            e_bis,
            self.sum_a,
            self.sum_b,
            self.q,
        )
        return Ctx(u, v, proof)

    def t_dec(self, ctx: Ctx, x: int):
        self.counter.inc_add(1)
        m = self.sk.commit.m * ctx.u * x
        e = self.BGV_polynomial.uniform_element(2)
        self.counter.inc_mult()
        u = m + self.q * e
        com_e = self.__commit(e)
        ds_proof = self.BGV_relation_prover.prove_ds(
            self.sk.commit.r, com_e.r, ctx.u, x, self.q
        )
        return (
            ds_proof,
            self.BGV_comm_scheme.commit(self.sk.commit),
            self.BGV_comm_scheme.commit(com_e),
            u,
        )

    def comb(self, ctx, d: list):
        d_u = []
        for i in d:
            self.BGV_relation_prover.verify_ds(
                *i[0], p=self.q, com_si=i[1], com_ei=i[2], ds=i[3]
            )
            d_u.append(i[3])
        round_and_pol = lambda x: self.cypari.Pol(self.cypari.round(x))
        Q_half = (self.Q - 1) / 2
        Q_half_q = Q_half % self.q
        helper_array = round_and_pol(np.ones(self.N) * Q_half)
        self.counter.inc_add(2)
        self.counter.inc_mod()
        ptx = self.cypari.liftall(
            ctx.v - sum(d_u) + helper_array
        ) * self.cypari.Mod(1, self.q)
        ptx -= round_and_pol(np.ones(self.N) * (Q_half_q))
        return ptx
