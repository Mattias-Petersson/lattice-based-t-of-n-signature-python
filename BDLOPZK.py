import math
from CommitmentScheme import CommitmentScheme
from type.classes import Commit, ProofOfOpen, ProofOfOpenLinear
from utils.Polynomial import Polynomial
import time
import cypari2


class BDLOPZK:
    def __init__(self, comm_scheme: CommitmentScheme):
        self.comm_scheme = comm_scheme
        self.polynomial = Polynomial(self.comm_scheme.N, self.comm_scheme.q)
        self.cypari = cypari2.Pari()

    def __verify_z_bound(self, z) -> bool:
        bound = int(4 * self.comm_scheme.sigma * math.sqrt(self.comm_scheme.N))
        for i in z:
            array_coeffs = self.polynomial.pol_to_arr(i)
            if self.polynomial.l2_norm(array_coeffs) >= bound:
                return False
        return True

    def __verify_z_multiple(self, *args):
        return all(self.__verify_z_bound(i.z) for i in args)

    def __verify_A1_z(self, proof: ProofOfOpenLinear, d):
        lhs = self.cypari(
            self.comm_scheme.A1 * self.cypari.mattranspose(proof.z)
        )
        rhs = self.cypari(proof.t + (d * proof.c[0][0]))
        return bool(self.cypari(lhs == rhs))

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

    def __make_proof_open(self, y, d, r) -> ProofOfOpen:
        t = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y))
        z = self.cypari.Vec(y + d * r)
        return ProofOfOpen(z, t)

    def __d_sigma(self):
        # TODO: This d should be a hash in order to be a Sigma protocol.
        return self.comm_scheme.get_challenge()

    def proof_of_opening(self, r) -> tuple[ProofOfOpen, cypari2.gen.Gen]:
        y = self.__make_y()
        d = self.__d_sigma()
        t = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y))
        z = self.cypari.Vec(y + d * r)
        return ProofOfOpen(z, t), d

    def verify_proof_of_opening(self, c1, proof: ProofOfOpen, d) -> bool:
        if not self.__verify_z_bound(proof.z):
            return False
        lhs = self.cypari(
            self.comm_scheme.A1 * self.cypari.mattranspose(proof.z)
        )
        rhs = self.cypari(proof.t + d * c1)

        return bool(self.cypari(lhs == rhs))

    def proof_of_linear_relation(
        self, r1, r2, g1, g2
    ) -> tuple[ProofOfOpen, ProofOfOpen, cypari2.gen.Gen, cypari2.gen.Gen]:
        y1, y2 = self.__make_y(), self.__make_y()
        d = self.__d_sigma()
        u = self.cypari(
            self.comm_scheme.A2
            * (
                g2 * self.cypari.mattranspose(y1)
                - g1 * self.cypari.mattranspose(y2)
            )
        )
        first_proof = self.__make_proof_open(y1, d, r1)
        second_proof = self.__make_proof_open(y2, d, r2)
        return first_proof, second_proof, u, d

    def verify_proof_of_linear_relation(
        self, proof_one: ProofOfOpenLinear, proof_two: ProofOfOpenLinear, u, d
    ) -> bool:
        if not self.__initial_check(proof_one, proof_two, d=d):
            return False
        lhs = self.cypari(
            self.comm_scheme.A2
            * (
                proof_two.g * self.cypari.mattranspose(proof_one.z)
                - proof_one.g * self.cypari.mattranspose(proof_two.z)
            )
        )
        rhs = self.cypari(
            (proof_two.g * proof_one.c[0][1] - proof_one.g * proof_two.c[0][1])
            * d
            + u
        )
        return bool(self.cypari(lhs == rhs))

    def __make_t(self, y):
        return self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y))

    def proof_of_sum(self, r1, r2, r3, g1, g2, g3) -> tuple[
        tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen],
        cypari2.gen.Gen,
        cypari2.gen.Gen,
    ]:
        d = self.__d_sigma()
        y = tuple(self.__make_y() for _ in range(3))
        r = r1, r2, r3
        t = [self.__make_t(i) for i in y]
        z = [self.cypari.Vec(y + d * r) for y, r in zip(y, r)]
        proof = tuple[ProofOfOpen, ProofOfOpen, ProofOfOpen](
            ProofOfOpen(z, t) for z, t in zip(z, t)
        )
        u = self.cypari(
            self.comm_scheme.A2
            * (
                g1 * self.cypari.mattranspose(y[0])
                + g2 * self.cypari.mattranspose(y[1])
                - g3 * self.cypari.mattranspose(y[2])
            )
        )
        return proof, u, d

    def verify_proof_of_sum(
        self,
        proof: tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear],
        u: cypari2.gen.Gen,
        d: cypari2.gen.Gen,
    ) -> bool:
        proof_one, proof_two, proof_three = proof
        if not self.__initial_check(*proof, d=d):
            return False

        lhs = self.cypari(
            self.comm_scheme.A2
            * (
                proof_one.g * self.cypari.mattranspose(proof_one.z)
                + proof_two.g * self.cypari.mattranspose(proof_two.z)
                - proof_three.g * self.cypari.mattranspose(proof_three.z)
            )
        )
        rhs = self.cypari(
            (
                proof_one.g * proof_one.c[0][1]
                + proof_two.g * proof_two.c[0][1]
                - proof_three.g * proof_three.c[0][1]
            )
            * d
            + u
        )
        return bool(self.cypari(lhs == rhs))


def commit(C: CommitmentScheme, m):
    r = C.r_commit()
    c = C.commit(Commit(m, r))
    return c, r


# TODO: These should be in tests rather than in loops.
def proof_of_open(comm_scheme: CommitmentScheme, ZK: BDLOPZK):
    m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    c, r = commit(comm_scheme, m)
    proof = ZK.proof_of_opening(r)
    open = ZK.verify_proof_of_opening(c[0][0], *proof)
    return open


def linear_relation(comm_scheme: CommitmentScheme, ZK: BDLOPZK, cypari):
    m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    g1 = comm_scheme.get_challenge()
    g2 = comm_scheme.get_challenge()
    c1, r1 = commit(comm_scheme, cypari(g1 * m))
    c2, r2 = commit(comm_scheme, cypari(g2 * m))
    first, second, *rest = ZK.proof_of_linear_relation(r1, r2, g1, g2)
    first = ProofOfOpenLinear(c1, g1, proof=first)
    second = ProofOfOpenLinear(c2, g2, proof=second)
    open = ZK.verify_proof_of_linear_relation(first, second, *rest)
    return open


def proof_of_sum(comm_scheme: CommitmentScheme, ZK: BDLOPZK, cypari):
    m1 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    m2 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    g1, g2, g3 = [comm_scheme.get_challenge() for _ in range(3)]
    c1, r1 = commit(comm_scheme, cypari(g3 * m1))
    c2, r2 = commit(comm_scheme, cypari(g3 * m2))
    c3, r3 = commit(comm_scheme, cypari(g1 * m1 + g2 * m2))
    proof, *rest = ZK.proof_of_sum(r1, r2, r3, g1, g2, g3)
    proof = tuple[ProofOfOpenLinear, ProofOfOpenLinear, ProofOfOpenLinear](
        ProofOfOpenLinear(c, g, proof=proof)
        for c, g, proof in [
            [c1, g1, proof[0]],
            [c2, g2, proof[1]],
            [c3, g3, proof[2]],
        ]
    )
    open = ZK.verify_proof_of_sum(proof, *rest)
    return open


def main():
    comm_scheme = CommitmentScheme()
    ZK = BDLOPZK(comm_scheme)
    cypari = cypari2.Pari()
    proofs = dict()
    clock = time.time()
    for _ in range(100):
        open = proof_of_open(comm_scheme, ZK)
        proofs[open] = proofs.get(open, 0) + 1
    print("Opening time: ", time.time() - clock)
    clock = time.time()
    for _ in range(100):
        open = linear_relation(comm_scheme, ZK, cypari)
        proofs[open] = proofs.get(open, 0) + 1
    print("Linear Relation time: ", time.time() - clock)
    clock = time.time()
    for _ in range(100):
        open = proof_of_sum(comm_scheme, ZK, cypari)
        proofs[open] = proofs.get(open, 0) + 1
    print("Sum time: ", time.time() - clock)
    clock = time.time()
    print(proofs)


if __name__ == "__main__":
    main()
