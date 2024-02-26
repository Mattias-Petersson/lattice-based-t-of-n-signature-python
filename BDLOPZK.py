import math
import re
from CommitmentSchemeCypari import CommitmentScheme
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
            array_coeffs = [int(j) for j in re.findall("(\\d+),", str(i))]
            if self.polynomial.l2_norm(array_coeffs) >= bound:
                return False
        return True

    def proof_of_opening(self, r):
        y = self.cypari.Vec(
            self.polynomial.gaussian_array(
                self.comm_scheme.k, self.comm_scheme.sigma
            )
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


def commit(C: CommitmentScheme, m):
    r = C.r_commit()
    c = C.commit(m, r)
    f = C.honest_func()
    # print("Successfully opens with f=1: {}".format(C.open(c, m, r, f)))
    return c, r


def main():
    CommScheme = CommitmentScheme()
    ZK = BDLOPZK(CommScheme)
    proofs = dict()
    for _ in range(100):
        m = ZK.polynomial.uniform_array(ZK.comm_scheme.l)
        c, r = commit(CommScheme, m)
        proof = ZK.proof_of_opening(r)
        open = ZK.verify_proof_of_opening(c[0][0], *proof)
        print(open)
        proofs[open] = proofs.get(open, 0) + 1
    print(proofs)


if __name__ == "__main__":
    main()
