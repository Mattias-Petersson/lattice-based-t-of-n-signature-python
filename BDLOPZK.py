import math
from CommitmentScheme import CommitmentScheme
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

    def __make_y(self):
        return self.polynomial.gaussian_array(
            self.comm_scheme.k, self.comm_scheme.sigma
        )

    def __d_sigma(self):
        # TODO: This d should be a hash in order to be a Sigma protocol.
        return self.comm_scheme.get_challenge()

    def __verify_A1_z(self, z, t, d, c):
        lhs = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z))
        rhs = self.cypari(t + (d * c))
        return bool(self.cypari(lhs == rhs))

    def proof_of_opening(self, r):
        y = self.__make_y()
        d = self.__d_sigma()
        dr = self.cypari(d * r)
        t = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y))
        z = self.cypari.Vec(y + dr)

        return z, t, d

    def verify_proof_of_opening(self, c1, z, t, d) -> bool:
        z_bounded = self.__verify_z_bound(z)
        lhs = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z))

        dc1 = self.cypari(d * c1)
        rhs = self.cypari(t + dc1)

        return bool(z_bounded and self.cypari(lhs == rhs))

    def proof_of_linear_relation(self, r1, r2, g1, g2):
        y1, y2 = self.__make_y(), self.__make_y()
        t1 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y1))
        t2 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y2))
        u = self.cypari(
            self.comm_scheme.A2
            * (
                g2 * self.cypari.mattranspose(y1)
                - g1 * self.cypari.mattranspose(y2)
            )
        )
        d = self.__d_sigma()
        z1 = self.cypari.Vec(y1 + d * r1)
        z2 = self.cypari.Vec(y2 + d * r2)
        return (t1, t2, u, z1, z2, d)

    def verify_proof_of_linear_relation(
        self, t1, t2, u, z1, z2, d, c1, c2, g1, g2
    ):
        if not (self.__verify_z_bound(z1) and self.__verify_z_bound(z2)):
            return False
        equivalences = []
        equivalences.append(self.__verify_A1_z(z1, t1, d, c1[0][0]))
        equivalences.append(self.__verify_A1_z(z2, t2, d, c2[0][0]))
        lhs3 = self.cypari(
            self.comm_scheme.A2
            * (
                g2 * self.cypari.mattranspose(z1)
                - g1 * self.cypari.mattranspose(z2)
            )
        )
        rhs3 = self.cypari((g2 * c1[0][1] - g1 * c2[0][1]) * d + u)
        equivalences.append(self.cypari(lhs3 == rhs3))
        return all(equivalences)

    def __make_t(self, y):
        return self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y))

    def __make_z_sum(self, y, d, r):
        return self.cypari.Vec(y + d * r)

    def proof_of_sum(self, r1, r2, r3, g1, g2, g3):
        y1, y2, y3 = self.__make_y(), self.__make_y(), self.__make_y()
        t1, t2, t3 = self.__make_t(y1), self.__make_t(y2), self.__make_t(y3)
        d = self.__d_sigma()
        z1, z2, z3 = (
            self.__make_z_sum(y1, d, r1),
            self.__make_z_sum(y2, d, r2),
            self.__make_z_sum(y3, d, r3),
        )
        u = self.cypari(
            self.comm_scheme.A2
            * (
                g1 * self.cypari.mattranspose(y1)
                + g2 * self.cypari.mattranspose(y2)
                - g3 * self.cypari.mattranspose(y3)
            )
        )

        return t1, t2, t3, u, z1, z2, z3, d

    def verify_proof_of_sum(
        self, t1, t2, t3, u, z1, z2, z3, d, c1, c2, c3, g1, g2, g3
    ):
        if not (self.__verify_z_bound(z1) and self.__verify_z_bound(z2)):
            return False
        equivalences = []

        equivalences.append(self.__verify_A1_z(z1, t1, d, c1[0][0]))
        equivalences.append(self.__verify_A1_z(z2, t2, d, c2[0][0]))
        equivalences.append(self.__verify_A1_z(z3, t3, d, c3[0][0]))

        lhs4 = self.cypari(
            self.comm_scheme.A2
            * (
                g1 * self.cypari.mattranspose(z1)
                + g2 * self.cypari.mattranspose(z2)
                - g3 * self.cypari.mattranspose(z3)
            )
        )
        rhs4 = self.cypari(
            (g1 * c1[0][1] + g2 * c2[0][1] - g3 * c3[0][1]) * d + u
        )
        equivalences.append(self.cypari(lhs4 == rhs4))

        return all(equivalences)


def commit(C: CommitmentScheme, m):
    r = C.r_commit()
    c = C.commit(m, r)
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
    proof = ZK.proof_of_linear_relation(r1, r2, g1, g2)
    open = ZK.verify_proof_of_linear_relation(*proof, c1, c2, g1, g2)
    return open


def proof_of_sum(comm_scheme: CommitmentScheme, ZK: BDLOPZK, cypari):
    m1 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    m2 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
    g1 = comm_scheme.get_challenge()
    g2 = comm_scheme.get_challenge()
    g3 = comm_scheme.get_challenge()
    c1, r1 = commit(comm_scheme, cypari(g3 * m1))
    c2, r2 = commit(comm_scheme, cypari(g3 * m2))
    c3, r3 = commit(comm_scheme, cypari(g1 * m1 + g2 * m2))
    proof = ZK.proof_of_sum(r1, r2, r3, g1, g2, g3)
    open = ZK.verify_proof_of_sum(*proof, c1, c2, c3, g1, g2, g3)
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
