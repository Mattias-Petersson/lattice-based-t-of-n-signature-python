import math
from Distributions import sampleGaussian
from testPolys2Again import CommitmentScheme
import numpy as np
from utils.PolyHelper import PolyHelper
from numpy.polynomial import Polynomial as pol
import numpy.linalg as lin


class BDLOPZK:

    def __init__(self, CommScheme: CommitmentScheme):
        self.CS = CommScheme
        self.PH = PolyHelper(self.CS.N, self.CS.q)

    def testEquivalences(self, y, d, r):
        print()
        A1 = self.CS.A1
        dr = self.PH.polymul(d, r)
        rd = self.PH.polymul(r, d)
        c1 = self.PH.matmul(A1, r)
        print("dc1 = a1dr = ", np.array_equal(
            self.PH.polymul(d, c1), self.PH.matmul(A1, dr)))
        print("rd = dr", np.array_equal(dr, rd))
        t = self.PH.matmul(A1, y)
        lhs1 = self.PH.matmul(A1, self.PH.add(y, dr))
        rhs1 = self.PH.polymul(d, self.PH.matmul(A1, r))
        # print("A_1*dr = A_1*rd", np.array_equal(lhs1, rhs1))
        # lhs2 = self.PH.add(t, lhs1)
        rhs2 = self.PH.add(t, rhs1)
        print(lhs1)
        print(rhs2)
        print("lhs = rhs", np.array_equal(lhs1, rhs2))

    def proofOfOpening(self, r):
        tempy = sampleGaussian(self.CS.k, self.CS.N, self.CS.sigma, self.CS.q)
        y = np.array([pol(np.zeros(self.CS.N)), pol(
            np.zeros(self.CS.N)), pol(np.zeros(self.CS.N))])
        for i in range(len(tempy)):
            y[i] = pol(tempy[i])
        t = self.PH.matmul(self.CS.A1, y)
        d = self.CS.getChallenge()
        self.testEquivalences(y, d, r)
        dr = self.PH.polymul(d, r)
        z = self.PH.add(y, dr)
        return (z, t, d)

    def checkProofOfOpening(self, A1, z, t, d, c):
        for poly in z:
            coef = poly.coef
            for i in range(len(coef)):
                if coef[i] > (self.CS.q-1)/2:
                    coef[i] = self.CS.q - coef[i]
            print("Within bounds:", lin.norm(coef, 2) <= (
                2 * self.CS.sigma * math.sqrt(self.CS.N)))
        lhs = self.PH.matmul(A1, z)
        dc1 = self.PH.polymul(d, c[0])
        rhs = self.PH.add(t, dc1)
        print(lhs)
        print(rhs)
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
    for _ in range(1):
        c, r = commit(CommScheme)
        A1 = CommScheme.A1
        proof = ZK.proofOfOpening(r)
        didProve = ZK.checkProofOfOpening(A1, *proof, c)
        proofs[didProve] = proofs.get(didProve, 0) + 1
    print(proofs)


if __name__ == "__main__":
    main()
