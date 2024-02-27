import math
import time
import cypari2
import numpy as np
import random
from utils.Polynomial import Polynomial


class CommitmentScheme:
    def __init__(
        self,
        l: int = 1,
        k: int = 3,
        n: int = 1,
        sbeta: int = 1,
        kappa: int = 36,
        q: int = 2**32 - 527,
        N: int = 1024,
    ):
        def __make_A1():
            A1_prime = self.polynomial.uniform_array((n, k - n))
            return self.cypari.concat(self.polynomial.ones(n), A1_prime)

        def __make_A2():
            zeroes = self.polynomial.uniform_array((self.n), 1)
            zeros_with_identity = self.cypari.matconcat(
                [zeroes, self.polynomial.ones(n)]
            )
            A2_prime = self.polynomial.uniform_array((l, k - n - l))
            return self.cypari.concat(zeros_with_identity, A2_prime)

        self.l = l
        self.k = k
        self.q = q
        self.n = n
        self.N = N
        self.sbeta = sbeta
        self.kappa = kappa
        if self.kappa > self.N:
            raise ValueError(
                "Kappa needs to be smaller than N to make a valid challenge."
            )
        self.sigma = math.floor(
            11 * self.kappa * 1 * math.sqrt(self.k * self.N)
        )
        self.polynomial = Polynomial(self.N, self.q)
        self.cypari = cypari2.Pari()
        self.A1 = __make_A1()
        self.A2 = __make_A2()
        self.A1A2 = self.cypari.matconcat(
            self.cypari.mattranspose([self.A1, self.A2])
        )

    def __a_with_message(self, x, r):
        """
        Returns A * r as well as a zero vector concatenated with the message
        that was sent in.
        With r bounded by S_b = 1 we do not need to reduce, but r_open allows
        for a less strict r.
        """
        Ar = self.cypari.Mat(self.A1A2 * self.cypari.mattranspose(r))
        zeroes = self.polynomial.uniform_array(self.n, 1)
        zeroes_message = self.cypari.matconcat(
            self.cypari.mattranspose([zeroes, x])
        )
        zeroes = self.cypari.Vec(zeroes_message)
        return Ar, zeroes_message

    def r_commit(self) -> list:
        return self.polynomial.uniform_bounded_array(self.k, self.sbeta + 1)

    def r_open(self) -> list:
        bound = math.floor(4 * self.sigma * math.sqrt(self.N))
        r = []
        while len(r) < 3:
            temp_r = np.random.randint(bound, size=self.N)
            if self.polynomial.l2_norm(temp_r) < bound:
                r.append(self.cypari.Pol(temp_r))
        return r

    def get_challenge(self):
        """
        Provides a challenge in the ring R_q with an l_inf norm of 1.
        Additionally it has a l_1 norm of kappa and is small in relation
        to N.
        """
        bound = self.N // 4
        indices = sorted(random.sample(range(bound), self.kappa), reverse=True)
        pol = [f"x^{i}" + random.choice([" + ", " - "]) for i in indices]
        pol = "".join(pol)[:-3]
        return self.polynomial.in_rq(self.cypari.Pol(pol))

    def honest_func(self):
        return self.cypari.Pol("1")

    def func_open(self) -> list:
        """
        f is a polynomial consisting of the difference of two small challenges.
        This will guaranteed have an l_2 norm of at most 2.
        """
        c1: cypari2.Gen = self.get_challenge()
        c2: cypari2.Gen = self.get_challenge()
        if self.cypari(c1 == c2):
            c1 = self.get_challenge()
        return self.cypari(c2 - c1)

    def commit(self, x: list, r: list) -> list:
        Ar, zerox = self.__a_with_message(x, r)
        return self.cypari(Ar + zerox)

    def open(self, commit, message, randomness, fun) -> bool:
        Ar, zerox = self.__a_with_message(message, randomness)
        fz = fun * zerox

        rhs = self.cypari(Ar + fz)
        lhs = self.cypari(fun * commit)
        return bool(self.cypari(lhs == rhs))


if __name__ == "__main__":
    start = time.time()
    comm = CommitmentScheme()
    cypa = Polynomial()
    print(
        "Time to make a commitment scheme and a polynomial class: %s seconds"
        % (round(time.time() - start, 4))
    )

    open = dict()
    for i in range(10):
        message = cypa.uniform_array(comm.l)
        randomness = comm.r_commit()
        commit = comm.commit(message, randomness)
        fun = comm.honest_func()
        opened = comm.open(commit, message, randomness, fun)
        open[opened] = open.get(opened, 0) + 1
    print(open)
    print("Total execution time: %s seconds" % (round(time.time() - start, 4)))
