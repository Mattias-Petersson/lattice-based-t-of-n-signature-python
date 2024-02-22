import numpy as np
from numpy.polynomial import Polynomial as pol
from numpy.polynomial import polynomial as polMath
import math


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

    def __element_from_Rq(self) -> pol:
        bound = (self.q - 1) // 2
        randomizedCoeffs = np.random.randint(
            low=-bound, high=bound, size=self.N)
        return pol(randomizedCoeffs)

    def basis_poly(self) -> np.ndarray:
        fx = np.zeros(self.N + 1)
        fx[[0, -1]] = 1
        return np.array([pol(fx)])

    def bounded_element(self, bound: int) -> pol:
        bound = (bound - 1) // 2 if bound % 2 == 1 else bound // 2
        return pol(np.random.randint(low=-bound, high=bound, size=self.N))

    def bounded_array(self, n: int, bound: int) -> np.ndarray:
        return np.array([self.bounded_element(bound) for _ in range(n)])

    def get_sbeta(self, l_inf: int) -> pol:
        return pol(np.random.randint(l_inf + 1, size=self.N))

    def array_Rq(self, n: int | tuple[int, int]) -> np.ndarray:
        def rqVector(n): return np.array(
            [self.__element_from_Rq() for _ in range(n)])
        if isinstance(n, int):
            return rqVector(n)
        i, j = n
        return np.array([rqVector(j) for _ in range(i)])

    def modulo(self, n: np.ndarray) -> np.ndarray:
        basis = self.basis_poly()
        nCopy = np.copy(n)
        nCopy = nCopy % basis
        return np.array(nCopy)

    def compare_reduced(self, n: np.ndarray, m: np.ndarray) -> bool:
        return np.array_equal(self.modulo(n), self.modulo(m))


if __name__ == "__main__":
    PH = PolyHelper(2, 2)
    PH.basis_poly()
