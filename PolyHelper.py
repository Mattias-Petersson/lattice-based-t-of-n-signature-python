import numpy as np
from numpy.polynomial import Polynomial as pol
from numpy.polynomial import polynomial as polMath


class PolyHelper:
    """
    Class that implements numpy's polynomial module with added functionality 
    to support getting ring elements, adding elements mod (q), and multiplying
    elements mod q and mod (x^N + 1)

    Args:
    N (int): the dimension of the polynomial ring, written as Rq[X] / (X^N+1)
    q (int): modulo for the coefficients. 

    """

    def __init__(self, N: int, q: int):
        self.N, self.q = N, q

    def basisPoly(self) -> pol:
        fx = np.zeros(self.N + 1)
        fx[[0, -1]] = 1
        return pol(fx)

    def elementFromRq(self) -> pol:
        randomizedCoeffs = np.random.randint(self.q, size=self.N)
        return pol(randomizedCoeffs)

    def boundedElement(self, bound: int) -> pol:
        return pol(np.random.randint(bound, size=self.N))

    def boundedArray(self, n: int, bound: int) -> np.ndarray:
        return np.array([self.boundedElement(bound) for _ in range(n)])

    def sBeta(self, l_inf: int) -> pol:
        return pol(np.random.randint(l_inf + 1, size=self.N))

    def arrayRq(self, n: int | tuple[int, int]) -> np.ndarray:
        def rqVector(n): return np.array(
            [self.elementFromRq() for _ in range(n)])
        if isinstance(n, int):
            return rqVector(n)
        i, j = n
        return np.array([rqVector(j) for _ in range(i)])

    def _helper(self, n: pol) -> pol:
        basis = self.basisPoly()
        nCopy = pol.copy(n)
        nCopy = nCopy % basis
        nCopy = pol([i % self.q for i in nCopy])
        return nCopy

    def _reduceRes(self, n: np.ndarray | pol) -> np.ndarray:
        if isinstance(n, pol):
            return np.array(self._helper(n))
        reducedn = np.copy(n)
        if reducedn.ndim == 1:
            return np.array([self._helper(i) for i in reducedn])
        else:
            return np.array([[self._helper(j) for j in i]for i in reducedn])

    def add(self, p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        sum = polMath.polyadd(p1, p2)
        for i in sum:
            i.coef = i.coef % self.q
        return sum

    def polymul(self, v1: pol, v2: pol | np.ndarray) -> np.ndarray:
        prod = polMath.polymul(v1, v2)
        res = self._reduceRes(prod)
        return res

    def matmul(self, p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        """
        Wrapper for numpy's matmul for matrices, with an additional call to
        reduce the coefficients mod q, and the polynomial degree mod X^N+1.
        """
        res = np.matmul(p1, p2)
        x = self._reduceRes(res)
        return x
