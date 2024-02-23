import cypari2
import numpy as np
import copy
import math


class PolyHelper2:
    def __init__(self, N: int = 1024, q: int = 2**32 - 527):
        self.cyp = cypari2.Pari()

        if not self.cyp.isprime(q):
            raise ValueError("q needs to be prime.")
        if not math.log2(N).is_integer():
            raise ValueError("N needs to be a power of two.")

        self.N = N
        self.q = q

    def __element_from_Rq(self) -> cypari2.gen.Gen:
        bound = (self.q - 1) // 2
        randomizedCoeffs = np.random.randint(
            low=-bound, high=bound, size=self.N
        )
        poly = self.cyp.Pol(randomizedCoeffs)
        # Ensure that the element is modulo f(x) and q.
        polyMod = self.cyp.Mod(self.cyp.Mod(poly, self.q), self.basis_poly())
        return polyMod

    def basis_poly(self) -> cypari2.gen.Gen:
        fx = f"x^{self.N+1} + 1"
        return self.cyp.Pol(fx)

    def array_Rq(self, n: int | tuple[int, int]) -> list:
        def rqVector(n):
            return [self.__element_from_Rq() for _ in range(n)]

        if isinstance(n, int):
            return rqVector(n)
        i, j = n
        return [rqVector(j) for _ in range(i)]


def testMatrices():
    vec = cyp("x + 1")
    matrix = cyp([["x + 1", "x + 1"], ["x + 1", "x + 1"]])
    print(matrix)
    test = cyp(matrix * matrix)
    print(test)


if __name__ == "__main__":
    cyp = cypari2.Pari()
    N = "23"
    ph = PolyHelper2(5, 23)
    testtest = ph.array_Rq((2, 2))
    testMatrices()
