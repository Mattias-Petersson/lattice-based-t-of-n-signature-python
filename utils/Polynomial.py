import cypari2
import numpy as np
import math


class Polynomial:
    """
    Helper class that implements Cypari to support polynomials over
    rings. This class has methods to return elements uniformly or
    Gaussianly from the ring, as well as converting polynomials
    to be in the ring (by taking the polynomial mod q and mod f(x)).
    """

    def __init__(self, N: int = 1024, q: int = 2**32 - 527):
        self.cyp = cypari2.Pari()

        if not self.cyp.isprime(q):
            raise ValueError("q needs to be prime.")
        if not math.log2(N).is_integer():
            raise ValueError("N needs to be a power of two.")

        self.N = N
        self.q = q

    def __uniform_element(self, bound: int = 0) -> cypari2.gen.Gen:
        if bound == 0:
            bound = (self.q - 1) // 2
        randomized_coeffs = np.random.randint(bound, size=self.N)
        return self.in_rq(self.cyp.Pol(randomized_coeffs))

    def __gaussian_element(self, sigma: int) -> cypari2.gen.Gen:
        """
        TODO: Verify that this is behaving similar to a Gaussian distribution.
        """
        unrounded = np.random.normal(0, sigma, size=self.N)
        poly = self.cyp.round(self.cyp.Pol(unrounded))
        return self.in_rq(poly)

    def __uniform_list(self, n: int, bound: int = 0):
        return [self.__uniform_element(bound) for _ in range(n)]

    def __gaussian_list(self, n: int, sigma: int):
        return [self.__gaussian_element(sigma) for _ in range(n)]

    def in_rq(self, poly) -> list:
        """
        Returns a polynomial congruent in R_q to the one sent in.

        Args:
        poly: A polynomial from the Cypari class.

        Returns:
        The polynomial that is congruent to the argument for the ring.
        """
        return self.cyp(
            poly * self.cyp.Mod(1, self.q) * self.cyp.Mod(1, self.basis_poly())
        )

    def basis_poly(self) -> cypari2.gen.Gen:
        fx = f"x^{self.N} + 1"
        return self.cyp.Pol(fx)

    def uniform_array(self, n: int | tuple[int, int], bound: int = 0) -> list:
        if isinstance(n, int):
            return self.cyp.vector(n, self.__uniform_list(n, bound))
        else:
            return self.cyp.matrix(*n, self.__uniform_list(n[0] * n[1], bound))

    def uniform_bounded_array(self, n: int, bound: int):
        return self.cyp.vector(n, self.__uniform_list(n, bound))

    def gaussian_array(self, n: int | tuple[int, int], sigma: int) -> list:
        if isinstance(n, int):
            return self.cyp.vector(n, self.__gaussian_list(n, sigma))
        else:
            return self.cyp.matrix(*n, self.__uniform_list(n[0] * n[1], sigma))

    def ones(self, n: int) -> list:
        return self.in_rq(self.cyp.matid(n))

    def l2_norm(self, list) -> float:
        return math.sqrt(sum([i**2 % self.q for i in list]))

    def concat(self, arr1, arr2, axis: int = 0):
        transposed = "~" if axis else ""
        return self.cyp.matconcat(f"[{arr1}, {arr2}]{transposed}")
