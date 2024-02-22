from Distributions import sampleGaussian
from testPolys2Again import CommitmentScheme
import numpy as np
from utils.PolyHelper import PolyHelper
from numpy.polynomial import Polynomial as pol


class BDLOPZK:

    def __init__(self, CommScheme: CommitmentScheme):
        self.CS = CommScheme
        self.PH = PolyHelper(self.CS.N, self.CS.q)

    def __make_y(self):
        distributions = sampleGaussian(3, self.CS.N, self.CS.sigma, self.CS.q)
        return np.array([pol(distributions[i]) for i in range(self.CS.k)])

    def proofOfOpening(self, r):
        y = self.__make_y()
        # TODO: Solve for too big t. (10^18 at least.)
        t = np.matmul(self.CS.A1, y)
        if np.linalg.norm(t[0].coef, np.inf) > (10**16):
            raise Exception(
                "Too big of a norm, this will cause loss of precision and might",
                " lead to erronous behavior.")
        d = self.CS.get_challenge()
        z = np.add(y, d * r)

        return (y, z, t, d)

    def checkProofOfOpening(self, z, t, d, c, r):
        lhs = np.matmul(self.CS.A1, z)
        dc1 = d * c
        rhs = np.add(t, dc1)
        return np.array_equal(lhs, rhs)


def commit(C: CommitmentScheme, m: np.ndarray):
    r = C.get_r_commit()
    c = C.commit(m, r)
    f = C.honest_f()
    print("Successfully opens with f=1: {}".format(C.open(c, m, r, f)))
    return c, r


def main():
    CommScheme = CommitmentScheme()
    ZK = BDLOPZK(CommScheme)
    proofs = dict()
    for _ in range(1):
        m = ZK.PH.array_Rq(CommScheme.l)
        c, r = commit(CommScheme, m)
        y, *proof = ZK.proofOfOpening(r)
        didProve = ZK.checkProofOfOpening(*proof, c=c, r=r)
        proofs[didProve] = proofs.get(didProve, 0) + 1
    print(proofs)


if __name__ == "__main__":
    main()
