import math
from CommitmentScheme import CommitmentScheme
from utils.Polynomial import Polynomial
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

    def proof_of_opening(self, r):
        y = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        # TODO: This d should be a hash in order to be a Sigma protocol.
        d = self.comm_scheme.get_challenge()
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

    def proof_of_linear_relation(self, r1, r2, g1, g2=[1]):
        y1 = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        y2 = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        t1 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y1))
        t2 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y2))
        u = self.cypari(
            self.comm_scheme.A2
            * (g2 * self.cypari.mattranspose(y1) - g1 * self.cypari.mattranspose(y2))
        )
        # TODO: This d should be a hash in order to be a Sigma protocol.
        d = self.comm_scheme.get_challenge()
        dr1 = self.cypari(d * r1)
        dr2 = self.cypari(d * r2)
        z1 = self.cypari.Vec(y1 + dr1)
        z2 = self.cypari.Vec(y2 + dr2)
        return (t1, t2, u, z1, z2, d)

    def verify_proof_of_linear_relation(self, t1, t2, u, z1, z2, d, c1, c2, g1, g2):
        if not (self.__verify_z_bound(z1) and self.__verify_z_bound(z2)):
            return False
        lhs1 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z1))
        rhs1 = self.cypari(t1 + (d * c1[0][0]))
        lhs2 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z2))
        rhs2 = self.cypari(t2 + (d * c2[0][0]))
        lhs3 = self.cypari(
            self.comm_scheme.A2
            * (g2 * self.cypari.mattranspose(z1) - g1 * self.cypari.mattranspose(z2))
        )
        rhs3 = self.cypari((g2 * c1[0][1] - g1 * c2[0][1]) * d + u)
        print(self.cypari(lhs3 == rhs3))
        return bool(
            self.cypari(lhs1 == rhs1)
            and self.cypari(lhs2 == rhs2)
            and self.cypari(lhs3 == rhs3)
        )

    def proof_of_sum(self, r1, r2, r3, g1, g2, g3):
        y1 = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        y2 = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        y3 = self.cypari.Vec(
            self.polynomial.gaussian_array(self.comm_scheme.k, self.comm_scheme.sigma)
        )
        t1 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y1))
        t2 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y2))
        t3 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(y3))
        u = self.cypari(
            self.comm_scheme.A2
            * (
                g1 * self.cypari.mattranspose(y1)
                + g2 * self.cypari.mattranspose(y2)
                - g3 * self.cypari.mattranspose(y3)
            )
        )
        # TODO: This d should be a hash in order to be a Sigma protocol.
        d = self.comm_scheme.get_challenge()
        dr1 = self.cypari(d * r1)
        dr2 = self.cypari(d * r2)
        dr3 = self.cypari(d * r3)
        z1 = self.cypari.Vec(y1 + dr1)
        z2 = self.cypari.Vec(y2 + dr2)
        z3 = self.cypari.Vec(y3 + dr3)
        return (t1, t2, t3, u, z1, z2, z3, d)

    def verify_proof_of_sum(self, t1, t2, t3, u, z1, z2, z3, d, c1, c2, c3, g1, g2, g3):
        if not (self.__verify_z_bound(z1) and self.__verify_z_bound(z2)):
            return False
        lhs1 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z1))
        rhs1 = self.cypari(t1 + (d * c1[0][0]))
        lhs2 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z2))
        rhs2 = self.cypari(t2 + (d * c2[0][0]))
        lhs3 = self.cypari(self.comm_scheme.A1 * self.cypari.mattranspose(z3))
        rhs3 = self.cypari(t3 + (d * c3[0][0]))
        lhs4 = self.cypari(
            self.comm_scheme.A2
            * (
                g1 * self.cypari.mattranspose(z1)
                + g2 * self.cypari.mattranspose(z2)
                - g3 * self.cypari.mattranspose(z3)
            )
        )
        rhs4 = self.cypari((g1 * c1[0][1] + g2 * c2[0][1] - g3 * c3[0][1]) * d + u)
        print(self.cypari(lhs4 == rhs4))
        return bool(
            self.cypari(lhs1 == rhs1)
            and self.cypari(lhs2 == rhs2)
            and self.cypari(lhs3 == rhs3)
            and self.cypari(lhs4 == rhs4)
        )


def commit(C: CommitmentScheme, m):
    r = C.r_commit()
    c = C.commit(m, r)
    return c, r


def main():
    CommScheme = CommitmentScheme()
    ZK = BDLOPZK(CommScheme)
    cypari = cypari2.Pari()
    proofs = dict()
    for _ in range(100):
        m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
        c, r = commit(CommScheme, m)
        proof = ZK.proof_of_opening(r)
        open = ZK.verify_proof_of_opening(c[0][0], *proof)
        proofs[open] = proofs.get(open, 0) + 1
    for _ in range(10):
        m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
        g1 = CommScheme.get_challenge()
        g2 = CommScheme.get_challenge()
        c1, r1 = commit(CommScheme, cypari(g1 * m))
        c2, r2 = commit(CommScheme, cypari(g2 * m))
        proof = ZK.proof_of_linear_relation(r1, r2, g1, g2)
        open = ZK.verify_proof_of_linear_relation(*proof, c1, c2, g1, g2)
        proofs[open] = proofs.get(open, 0) + 1
    for _ in range(10):
        m1 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
        m2 = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
        g1 = CommScheme.get_challenge()
        g2 = CommScheme.get_challenge()
        g3 = CommScheme.get_challenge()
        c1, r1 = commit(CommScheme, cypari(g3 * m1))
        c2, r2 = commit(CommScheme, cypari(g3 * m2))
        c3, r3 = commit(CommScheme, cypari(g1 * m1 + g2 * m2))
        proof = ZK.proof_of_sum(r1, r2, r3, g1=g1, g2=g2, g3=g3)
        open = ZK.verify_proof_of_sum(*proof, c1, c2, c3, g1, g2, g3)
        proofs[open] = proofs.get(open, 0) + 1
    print(proofs)


if __name__ == "__main__":
    main()
