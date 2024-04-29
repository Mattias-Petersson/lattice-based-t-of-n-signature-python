import math
import cypari2
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from type.classes import (
    Commit,
    ProofOfOpen,
    ProofOfSpecificOpen,
    ProofOfOpenLinear,
)


class BDLOP:
    def __init__(self, comm_scheme: BDLOPCommScheme):
        self.comm_scheme = comm_scheme
        self.polynomial = comm_scheme.polynomial
        self.cypari = self.polynomial.cypari

    def __verify_z_bound(self, z) -> bool:
        bound = int(4 * self.comm_scheme.sigma * math.sqrt(self.comm_scheme.N))
        for i in z:
            if self.polynomial.l2_norm(i) >= bound:
                return False
        return True

    def __verify_z_multiple(self, *args):
        return all(self.__verify_z_bound(i.z) for i in args)

    def __verify_A1_z(self, proof: ProofOfOpenLinear, d):
        lhs = self.comm_scheme.A1 * self.cypari.mattranspose(proof.z)
        rhs = proof.t + d * proof.c[0][0]
        return lhs == rhs

    def __verify_A1_z_multiple(self, *args, d):
        return all(self.__verify_A1_z(proof, d) for proof in args)

    def __initial_check(self, *args, d):
        z_bounded = self.__verify_z_multiple(*args)
        a1_z = self.__verify_A1_z_multiple(*args, d=d)
        return z_bounded and a1_z

    def __make_y(self):
        return self.polynomial.gaussian_array(
            self.comm_scheme.k, self.comm_scheme.sigma
        )

    def d_sigma(self, *args):
        return self.polynomial.hash(self.comm_scheme.kappa, *args)

    def __make_lhs(self, A, vector) -> cypari2.gen.Gen:
        return A * self.cypari.mattranspose(vector)

    def __make_rhs(self, t, d, c) -> cypari2.gen.Gen:
        return t + d * c

    def __A1_A2(self) -> tuple[cypari2.gen.Gen, cypari2.gen.Gen]:
        return (self.comm_scheme.A1, self.comm_scheme.A2)

    def __check_equivalences(self, lhs: tuple, rhs: tuple) -> bool:
        return all(l == r for l, r in zip(lhs, rhs))

    def proof_of_opening(self, r) -> ProofOfOpen:
        y = self.__make_y()
        t = self.__make_lhs(self.comm_scheme.A1, y)
        d = self.d_sigma(t)
        z = self.cypari.Vec(self.__make_rhs(y, d, r))
        return ProofOfOpen(z, t)

    def proof_of_specific_opening(self, r) -> ProofOfSpecificOpen:
        y = self.__make_y()
        t = tuple(self.__make_lhs(A, y) for A in self.__A1_A2())
        d = self.d_sigma(*t)
        z = self.cypari.Vec(self.__make_rhs(y, d, r))
        return ProofOfSpecificOpen(z, *t)

    def verify_proof_of_opening(self, c1, proof: ProofOfOpen) -> bool:
        if not self.__verify_z_bound(proof.z):
            return False
        lhs = self.__make_lhs(self.comm_scheme.A1, proof.z)
        d = self.d_sigma(proof.t)
        rhs = self.__make_rhs(proof.t, d, c1)
        return self.__check_equivalences(lhs, rhs)

    def verify_proof_of_specific_opening(
        self, c1, c2, proof: ProofOfSpecificOpen, m
    ) -> bool:
        if not self.__verify_z_bound(proof.z):
            return False
        r0 = (self.cypari.Pol("0") for _ in range(3))
        cprime = commit_with_r(self.comm_scheme, m, r0)
        c1 = c1 - cprime[0][0]
        c2 = c2 - cprime[0][1]
        d = self.d_sigma(proof.t1, proof.t2)

        lhs = tuple(self.__make_lhs(A, proof.z) for A in self.__A1_A2())
        rhs = tuple(
            self.__make_rhs(t, d, c)
            for t, c in zip((proof.t1, proof.t2), (c1, c2))
        )
        return self.__check_equivalences(lhs, rhs)

    def verify_proof_of_zero_opening(
        self, c1, c2, proof: ProofOfSpecificOpen
    ) -> bool:
        d = self.d_sigma(proof.t1, proof.t2)
        if not self.__verify_z_bound(proof.z):
            return False

        lhs = tuple(self.__make_lhs(A, proof.z) for A in self.__A1_A2())
        rhs = tuple(
            self.__make_rhs(t, d, c)
            for t, c in zip((proof.t1, proof.t2), (c1, c2))
        )
        return self.__check_equivalences(lhs, rhs)

    def proof_of_linear_relation(
        self, r1, r2, g1, g2
    ) -> tuple[ProofOfOpen, ProofOfOpen, cypari2.gen.Gen]:
        y = [self.__make_y() for _ in range(2)]
        u = self.comm_scheme.A2 * (
            g2 * self.cypari.mattranspose(y[0])
            - g1 * self.cypari.mattranspose(y[1])
        )
        t = tuple(self.__make_lhs(self.comm_scheme.A1, i) for i in y)
        d = self.d_sigma(*t, g1, g2)
        z = self.cypari.Vec(y + d * r for y, r in zip(y, (r1, r2)))
        return ProofOfOpen(z[0], t[0]), ProofOfOpen(z[1], t[1]), u

    def verify_proof_of_linear_relation(
        self, proof: tuple[ProofOfOpenLinear, ProofOfOpenLinear], u
    ) -> bool:
        d = self.d_sigma(proof[0].t, proof[1].t, proof[0].g, proof[1].g)
        if not self.__initial_check(*proof, d=d):
            return False
        lhs = self.comm_scheme.A2 * (
            proof[1].g * self.cypari.mattranspose(proof[0].z)
            - proof[0].g * self.cypari.mattranspose(proof[1].z)
        )

        rhs = (
            proof[1].g * proof[0].c[0][1] - proof[0].g * proof[1].c[0][1]
        ) * d + u

        return self.__check_equivalences(lhs, rhs)

    def proof_of_sum(self, r1, r2, r3, g1, g2, g3) -> tuple[
        tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen],
        cypari2.gen.Gen,
    ]:
        y = tuple(self.__make_y() for _ in range(3))
        r = r1, r2, r3
        t = tuple(self.__make_lhs(self.comm_scheme.A1, i) for i in y)
        d = self.d_sigma(*t)
        z = tuple(self.cypari.Vec(y + d * r) for y, r in zip(y, r))
        proof = tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen](
            ProofOfOpen(z, t) for z, t in zip(z, t)
        )
        u = self.comm_scheme.A2 * (
            g1 * self.cypari.mattranspose(y[0])
            + g2 * self.cypari.mattranspose(y[1])
            - g3 * self.cypari.mattranspose(y[2])
        )
        return proof, u

    def verify_proof_of_sum(
        self,
        proof: tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear],
        u: cypari2.gen.Gen,
    ) -> bool:
        t = (proof.t for proof in proof)
        d = self.d_sigma(*t)
        if not self.__initial_check(*proof, d=d):
            return False
        lhs = self.comm_scheme.A2 * (
            proof[0].g * self.cypari.mattranspose(proof[0].z)
            + proof[1].g * self.cypari.mattranspose(proof[1].z)
            - proof[2].g * self.cypari.mattranspose(proof[2].z)
        )
        rhs = (
            proof[0].g * proof[0].c[0][1]
            + proof[1].g * proof[1].c[0][1]
            - proof[2].g * proof[2].c[0][1]
        ) * d + u
        return self.__check_equivalences(lhs, rhs)

    def proof_of_triple_sum(self, r1, r2, r3, r4, g1, g2, g3, g4) -> tuple[
        tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen, ProofOfOpen],
        cypari2.gen.Gen,
    ]:
        y = tuple(self.__make_y() for _ in range(4))
        r = r1, r2, r3, r4
        t = tuple(self.__make_lhs(self.comm_scheme.A1, i) for i in y)
        d = self.d_sigma(*t)
        z = tuple(self.cypari.Vec(y + d * r) for y, r in zip(y, r))
        proof = tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen, ProofOfOpen](
            ProofOfOpen(z, t) for z, t in zip(z, t)
        )
        u = self.comm_scheme.A2 * (
            g1 * self.cypari.mattranspose(y[0])
            + g2 * self.cypari.mattranspose(y[1])
            + g3 * self.cypari.mattranspose(y[2])
            - g4 * self.cypari.mattranspose(y[3])
        )
        return proof, u

    def verify_proof_of_triple_sum(
        self,
        proof: tuple[
            ProofOfOpenLinear,
            ProofOfOpenLinear,
            ProofOfOpenLinear,
            ProofOfOpenLinear,
        ],
        u: cypari2.gen.Gen,
    ) -> bool:
        t = (proof.t for proof in proof)
        d = self.d_sigma(*t)
        if not self.__initial_check(*proof, d=d):
            return False
        lhs = self.comm_scheme.A2 * (
            proof[0].g * self.cypari.mattranspose(proof[0].z)
            + proof[1].g * self.cypari.mattranspose(proof[1].z)
            + proof[2].g * self.cypari.mattranspose(proof[2].z)
            - proof[3].g * self.cypari.mattranspose(proof[3].z)
        )
        rhs = (
            proof[0].g * proof[0].c[0][1]
            + proof[1].g * proof[1].c[0][1]
            + proof[2].g * proof[2].c[0][1]
            - proof[3].g * proof[3].c[0][1]
        ) * d + u

        return self.__check_equivalences(lhs, rhs)


def commit(C: BDLOPCommScheme, m):
    r = C.r_commit()
    c = C.commit(Commit(m, r))
    return c, r


def commit_with_r(C: BDLOPCommScheme, m, r):
    c = C.commit(Commit(m, r))
    return c


def proof_of_open(comm_scheme: BDLOPCommScheme, ZK: BDLOP):
    m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    c, r = commit(comm_scheme, m)
    proof = ZK.proof_of_opening(r)
    open = ZK.verify_proof_of_opening(c[0][0], proof)
    return open


def proof_of_specific_open(comm_scheme: BDLOPCommScheme, ZK: BDLOP):
    m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    c, r = commit(comm_scheme, m)
    proof = ZK.proof_of_specific_opening(r)
    open = ZK.verify_proof_of_specific_opening(c[0][0], c[0][1], proof, m)
    return open


def linear_relation(comm_scheme: BDLOPCommScheme, ZK: BDLOP):
    m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    g = [comm_scheme.get_challenge() for _ in range(2)]

    c1, r1 = commit(comm_scheme, g[0] * m)
    c2, r2 = commit(comm_scheme, g[1] * m)
    first, second, u = ZK.proof_of_linear_relation(r1, r2, *g)
    first = ProofOfOpenLinear(c1, g[0], proof=first)
    second = ProofOfOpenLinear(c2, g[1], proof=second)
    open = ZK.verify_proof_of_linear_relation((first, second), u)
    return open


def proof_of_sum(comm_scheme: BDLOPCommScheme, ZK: BDLOP):
    m1 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    m2 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    g1, g2, g3 = [comm_scheme.get_challenge() for _ in range(3)]
    c1, r1 = commit(comm_scheme, g3 * m1)
    c2, r2 = commit(comm_scheme, g3 * m2)
    c3, r3 = commit(comm_scheme, g1 * m1 + g2 * m2)
    proof, u = ZK.proof_of_sum(r1, r2, r3, g1, g2, g3)
    proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
        ProofOfOpenLinear(c, g, proof=proof)
        for c, g, proof in [
            [c1, g1, proof[0]],
            [c2, g2, proof[1]],
            [c3, g3, proof[2]],
        ]
    )
    open = ZK.verify_proof_of_sum(proof, u)
    return open
