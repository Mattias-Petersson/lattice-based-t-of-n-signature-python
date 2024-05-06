from GKS23.MultiCounter import MultiCounter
import math
import hashlib
import cypari2
from numpy.random import Generator, PCG64
from type.classes import poly


class Polynomial:
    """
    Helper class that implements Cypari to support polynomials over
    rings. This class has methods to return elements uniformly or
    Gaussianly from the ring, as well as converting polynomials
    to be in the ring (by taking the polynomial mod q and mod f(x)).
    """

    def __init__(
        self,
        counter: MultiCounter,
        q: int = 2**32 - 527,
        N: int = 1024,
    ):
        self.cypari: cypari2.pari_instance.Pari = cypari2.Pari()
        self.cypari.allocatemem(10**10)

        if not self.cypari.isprime(q):
            raise ValueError("q needs to be prime.")

        self.gen = Generator(PCG64())
        self.q = q
        self.counter = counter
        self.N = N

    def uniform_element(self, bound: int = 0) -> poly:
        """
        Returns a uniformly distributed polynomial.
        """

        if bound == 0:
            bound = (self.q - 1) // 2

        randomized_coeffs = self.gen.integers(bound, size=self.N)
        return self.in_rq(self.cypari.Pol(randomized_coeffs))

    def gaussian_element(self, sigma: int) -> poly:
        """
        Returns an element from a rounded continuous Gaussian distribution.
        This distribution is used instead of a discrete Gaussian distribution.
        """
        unrounded = self.gen.normal(0, sigma, size=self.N)
        pol = self.cypari.round(self.cypari.Pol(unrounded))
        return self.in_rq(pol)

    def in_rq(self, p: poly):
        """
        Returns a polynomial congruent in R_q to the one sent in.

        Args:
        p: A polynomial or a list of polynomials.

        Returns:
        The polynomial that is congruent to the argument for the ring.
        """
        self.counter.inc_mod(2)
        return (
            p
            * self.cypari.Mod(1, self.q)
            * self.cypari.Mod(1, self.basis_poly())
        )

    def basis_poly(self) -> poly:
        """
        Returns the basis polynomial for this instance. The basis polynomial
        is going to be in the form "x^N + 1", where N is a power of two.
        """
        fx = f"x^{self.N} + 1"
        return self.cypari.Pol(fx)

    def __shape_helper(self, n: int | tuple[int, int], func_one_element):
        """
        What we want to return will depend on n. If n is an integer, we want to
        return a single element if n = 1, an array if n!=1, and a matrix of
        specified dimension if n is a tuple. This helper method takes in
        functions to get the element and returns the proper structure.
        """

        def func_mult(n, bound):
            return [func_one_element(bound) for _ in range(n)]

        if isinstance(n, int):
            return lambda n, bound: (
                func_one_element(bound)
                if n == 1
                else self.cypari.vector(n, func_mult(n, bound))
            )
        return lambda n, bound: self.cypari.matrix(
            *n, func_mult(n[0] * n[1], bound)
        )

    def uniform_array(
        self, n: int | tuple[int, int], bound: int = 0
    ) -> poly | list[poly]:
        """
        Returns a list of polynomials, where each polynomial is created
        according to a uniform distribution.

        Args:
        n (int | tuple[int, int]): The shape of the output. If it is 1,
        one element is returned as if we were calling on uniform_element.
        If it is an integer other than 1, an array gets sent back. If a tuple
        is sent in, a matrix is returned.

        bound (int): the upper bound for the polynomials
        """
        func = self.__shape_helper(n, self.uniform_element)
        return func(n, bound)

    def gaussian_array(
        self, n: int | tuple[int, int], sigma: int
    ) -> poly | list[poly]:
        """
        Returns a list of polynomials, where each polynomial is created
        according to a Gaussian distribution.

        Args:
        n (int | tuple[int, int]): The shape of the output. If it is 1,
        one element is returned as if we were calling on uniform_element.
        If it is an integer other than 1, an array gets sent back. If a tuple
        is sent in, a matrix is returned.

        sigma (int): The standard deviation to use
        """
        func = self.__shape_helper(n, self.gaussian_element)
        return func(n, sigma)

    def guassian_bounded_array(
        self, n: int | tuple[int, int], sigma: int, bound: int
    ) -> poly | list[poly]:
        """
        Creates a list of polynomials according to a Gaussian distribution,
        then checks so that this falls within a certain bound for the values.
        If it doesn't, a new one is created until it satisfies.
        """

        def bounded_element(sigma):
            r = self.gaussian_element(sigma)
            while self.l2_norm(r) > bound:
                r = self.gaussian_element(sigma)
            return r

        func = self.__shape_helper(n, bounded_element)
        return func(n, sigma)

    def ones(self, n: int) -> list[poly]:
        """
        Creates an identity matrix in the polynomial's space.
        """
        return self.in_rq(self.cypari.matid(n))

    def l2_norm(self, pol: poly) -> float:
        """
        Takes the l2 norm of a polynomial by first converting it to
        an integer array.
        """
        lst = self.pol_to_arr(pol)
        return math.sqrt(sum(i**2 % self.q for i in lst))

    def pol_to_arr(self, pol: poly) -> list[int]:
        """
        Convert a polynomial to an array of integers.
        """
        pari_vec = self.cypari.Vec(self.cypari.liftall(pol))
        return pari_vec

    def challenge(self, kappa: int, seed: list[int] | None = None) -> poly:
        """
        Provides a polynomial in the ring R_q with an l_inf norm of one.
        Additionally, it has a l_1 norm of kappa and should be small in
        relation to N. We limit the degree of the polynomial to one fourth
        of N. A seed can be supplied to always produce the same output
        polynomial, which is useful for mapping a hash to a polynomial.
        """
        gen = Generator(PCG64(seed))
        bound = self.N // 4
        indices = gen.choice(range(bound), size=kappa, replace=False)
        coeffs = gen.choice(["+", "-"], size=kappa)
        pol = ""
        for i, j in zip(coeffs, indices):
            pol += i + f"x^{j}"
        return self.cypari.Pol(pol)

    def challenge_vector(self, n: int, kappa: int):
        """
        Returns a vector of small challenges. These challenges all have an
        l_inf norm of one. Calls the challenge method for n entries.
        """
        return self.cypari.vector(n, [self.challenge(kappa) for _ in range(n)])

    def small_invertible(self, kappa: int) -> poly:
        """
        The difference of two challenges c will have an l_inf norm of at
        most two. As such, all elements here will be invertible in R_q.
        """
        c1 = self.challenge(kappa)
        c2 = self.challenge(kappa)
        while c1 == c2:
            c1 = self.challenge(kappa)
        self.counter.inc_add()
        return c2 - c1

    def hash(self, kappa: int, *args) -> cypari2.gen.Gen:
        """
        Hash an input of an arbitrary number of polynomial arrays, outputting
        a single polynomial.
        """
        h = hashlib.sha384()
        for i in args:
            h.update(str.encode(str(i)))
        integers_hash: list[int] = list(h.digest())
        return self.challenge(kappa=kappa, seed=integers_hash)
