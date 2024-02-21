import math
from numpy.polynomial import Polynomial as pol
from numpy.polynomial import polynomial as polMath
import numpy as np
from utils.PolyHelper import PolyHelper
import numpy.linalg as lin


class CommitmentScheme:
    def __init__(self, l: int = 1, k: int = 3, n: int = 1, q: int = 2 ** 32 - 527, N: int = 1024):
        def _makeA1():
            A1prime = self.PH.arrayRq((n, k-n))
            return np.concatenate((np.identity(n), A1prime), axis=1)

        def _makeA2():
            A2prime = self.PH.arrayRq((l, k-n-l))
            return np.concatenate(
                (np.zeros((l, n)), np.identity(l), A2prime), axis=1)
        self.l = l
        self.k = k
        self.q = q
        self.n = n
        self.uniformValues = ((q-1)/2, (q-1)/2, q)
        self.N = N
        self.kappa = 36
        self.sigma = math.floor(11 * self.kappa * 1 *
                                math.sqrt(self.k * self.N))
        self.PH = PolyHelper(self.N, self.q)
        self.A1 = _makeA1()
        self.A2 = _makeA2()
        self.A1A2 = np.concatenate((self.A1, self.A2))

    def getRCommit(self) -> np.ndarray:
        return np.array([self.PH.sBeta(1) for _ in range(self.k)])

    def getROpen(self) -> np.ndarray:
        bound = math.floor(4 * self.sigma * math.sqrt(self.N))
        r = C.PH.boundedArray(self.k, round(bound / 20))
        for poly in r:
            while lin.norm(poly.coef, 2) > bound:
                poly.coef = C.PH.boundedElement(bound).coef
        return r

    def getF(self) -> pol:
        c1 = self.getChallenge()
        c2 = self.getChallenge()
        while (np.array_equal(c1.coef, c2.coef)):
            c1 = self.getChallenge()
        cDiff = polMath.polysub(c1, c2)[0]
        return cDiff

    def getChallenge(self) -> pol:
        """
        We need a challenge in the ring R_q, with an l_inf norm of 1, 
        and a l_1 norm of kappa.
        """
        remainingOnes = self.kappa
        bound = math.floor(self.N / 4)
        c = np.zeros(bound)
        while (remainingOnes > 0):
            idx = np.random.randint(len(c))
            if (c[idx]) == 0:
                c[idx] = np.random.choice([-1, 1])
                remainingOnes -= 1
        return pol(c)

    def commit(self, x: np.ndarray, r: np.ndarray) -> np.ndarray:
        Ar = self.PH.matmul(self.A1A2, r)
        zerox = np.concatenate((np.zeros(self.n), x))
        return self.PH.add(Ar, zerox)

    def open(self, C: np.ndarray, x: np.ndarray, r: np.ndarray, f: pol) -> bool:
        Ar = self.PH.matmul(self.A1A2, r)
        zerox = np.concatenate((np.zeros(self.n), x))
        fz = self.PH.polymul(f, zerox)
        rhs = self.PH.add(Ar, fz)
        lhs = self.PH.polymul(f, C)
        return np.array_equal(lhs, rhs)


if __name__ == "__main__":
    C = CommitmentScheme()
    open = dict()
    for i in range(1000):
        m = np.array([C.PH.elementFromRq() for _ in range(C.l)])
        comm = [C.getRCommit(), C.getROpen()]
        i = np.random.randint(2)
        r = comm[i]
        f = pol([1])
        # f = C.getF()
        c = C.commit(m, r)
        opened = C.open(c, m, r, f)
        open[opened] = open.get(opened, 0) + 1
    print("Open: ", open)

    # print("Test", test[0], test.shape)
