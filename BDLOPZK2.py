import math
from BasicFunctions import sampleGaussian, sampleUniform
from testPolys2Again import CommitmentScheme
import numpy as np
from PolyHelper import PolyHelper
import numpy.linalg as lin
from numpy.polynomial import Polynomial as pol


class BDLOPZK:

    def __init__(self, CommScheme: CommitmentScheme):
        self.CS = CommScheme
        self.PH = PolyHelper(self.CS.N, self.CS.q)

    def proofOfOpening(self):
        self.y = sampleGaussian(self.CS.k, np.zeros(
            self.CS.k), self.CS.sigma, self.CS.q)
        self.t = self.PH.matmul(self.CS.A1, self.y)
        self.d = self.CS.getChallenge()
        self.r = self.CS.getRCommit()
        dr = self.PH.polymul(self.d, self.r)
        z = self.PH.add(self.y, dr)
        return z

    def checkProofOfOpening(self, A1, z, c, r):
        for poly in z:
            print("Within bounds:", lin.norm(poly.coef, 2) <= (
                2 * self.CS.sigma * math.sqrt(self.CS.N)))
        lhs = self.PH.matmul(A1, z)
        dc1 = self.PH.polymul(self.d, c[0])
        rhs = self.PH.add(self.t, dc1)
        return np.array_equal(lhs, rhs)


def commit(C: CommitmentScheme):
    m = np.array([C.PH.elementFromRq() for _ in range(C.l)])
    r = C.getRCommit()
    c = C.commit(m, r)
    print("Successfully opens with f=1: {}".format(C.open(c, m, r, pol([1]))))
    return c, r


def main():
    CommScheme = CommitmentScheme()
    ZK = BDLOPZK(CommScheme)
    proofs = dict()
    for _ in range(100):
        c, r = commit(CommScheme)
        A1 = CommScheme.A1
        z = ZK.proofOfOpening()
        didProve = ZK.checkProofOfOpening(A1, z, c, r)
        proofs[didProve] = proofs.get(didProve, 0) + 1
    print(proofs)


if __name__ == "__main__":
    main()
