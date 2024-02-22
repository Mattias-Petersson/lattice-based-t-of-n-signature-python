import math
from numpy.polynomial import Polynomial as pol
import numpy as np
from utils.PolyHelper import PolyHelper
import numpy.linalg as lin
import time


class CommitmentScheme:
    def __init__(self, l: int = 1, k: int = 3, n: int = 1, q: int = 2 ** 32 - 527, N: int = 1024):
        def __make_A1():
            A1prime = self.PH.array_Rq((n, k-n))
            return np.concatenate((np.identity(n), A1prime), axis=1)

        def __make_A2():
            A2prime = self.PH.array_Rq((l, k-n-l))
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
        self.A1 = __make_A1()
        self.A2 = __make_A2()
        self.A1A2 = np.concatenate((self.A1, self.A2))

    def get_r_commit(self) -> np.ndarray:
        return np.array([self.PH.get_sbeta(1) for _ in range(self.k)])

    def get_r_open(self) -> np.ndarray:
        bound = math.floor(4 * self.sigma * math.sqrt(self.N))
        r = self.PH.bounded_array(self.k, round(bound / 20))
        for poly in r:
            while lin.norm(poly.coef, 2) > bound:
                poly.coef = C.PH.bounded_element(bound).coef
        return r

    def __zeros_poly(self):
        temp = np.zeros(self.N)
        polTemp = pol(temp)
        return np.array([polTemp])

    def __a_with_message(self, x, r) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns A * r as well as a zero vector concatenated with the message
        that was sent in. 
        With r bounded by S_b = 1 we do not need to reduce, but r_open allows
        for a less strict r. 
        """
        Ar = np.matmul(self.A1A2, r)
        Ar = self.PH.modulo(Ar)
        zerox = np.concatenate((self.__zeros_poly(), x))
        return Ar, zerox

    def __compare_reduced(self, lhs, rhs) -> bool:
        return np.array_equal(self.PH.modulo(lhs), self.PH.modulo(rhs))

    def get_f(self) -> np.ndarray:
        """
        f is a polynomial consisting of the difference of two small challenges.
        This will guaranteed have an l_2 norm of at most 2.
        """
        c1 = self.get_challenge()
        c2 = self.get_challenge()
        while (np.array_equal(c1, c2)):
            c1 = self.get_challenge()
        cDiff = np.subtract(c2, c1)
        return np.array([pol(cDiff)])

    def honest_f(self) -> np.ndarray:
        return np.array([pol([1])])

    def get_challenge(self) -> np.ndarray:
        """
        Provides a challenge in the ring R_q with an l_inf norm of 1. 
        Additionally it has a l_1 norm of kappa. 
        #TODO: This will cause an infinite loop if kappa > N.
        """
        remainingOnes = self.kappa
        bound = self.N // 4
        c = np.zeros(bound)
        while (remainingOnes > 0):
            idx = np.random.randint(len(c))
            if (c[idx]) == 0:
                c[idx] = np.random.choice([-1, 1])
                remainingOnes -= 1
        return np.array([pol(c)])

    def commit(self, x: np.ndarray, r: np.ndarray) -> np.ndarray:
        Ar, zerox = self.__a_with_message(x, r)
        return np.add(Ar, zerox)

    def open(self, C: np.ndarray, x: np.ndarray, r: np.ndarray, f: np.ndarray) -> bool:
        Ar, zerox = self.__a_with_message(x, r)
        fz: np.ndarray = f * zerox
        rhs = np.add(Ar, fz)
        lhs = f * C
        return self.__compare_reduced(lhs, rhs)


if __name__ == "__main__":
    start = time.time()
    C = CommitmentScheme()
    PH = PolyHelper(C.N, C.q)

    open = dict()
    for i in range(100):
        m = PH.array_Rq(C.l)
        r = C.get_r_commit()
        f = C.honest_f()
        c = C.commit(m, r)
        C.PH.modulo(c)
        opened = C.open(c, m, r, f)
        open[opened] = open.get(opened, 0) + 1
    print("Open: ", open)
    print("Execution time: %s seconds" % (round(time.time() - start, 4)))
