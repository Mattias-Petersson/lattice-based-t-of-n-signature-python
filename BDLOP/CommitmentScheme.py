import math
import time
import cypari2
import numpy as np
from utils.Polynomial import Polynomial
from type.classes import Commit, CommitOpen


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
                [zeroes, self.polynomial.ones(l)]
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
        self.cypari = self.polynomial.cypari
        self.A1 = __make_A1()
        self.A2 = __make_A2()
        self.A1A2 = self.cypari.matconcat(
            self.cypari.mattranspose([self.A1, self.A2])
        )

    def __a_with_message(self, c: Commit):
        """
        Returns A * r as well as a zero vector concatenated with the message
        that was sent in.
        With r bounded by S_b = 1 we do not need to reduce, but r_open allows
        for a less strict r.
        """
        Ar = self.cypari.Mat(self.A1A2 * self.cypari.mattranspose(c.r))
        zeroes = self.polynomial.uniform_array(self.n, 1)
        zeroes_message = self.cypari.matconcat(
            self.cypari.mattranspose([zeroes, c.m])
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
        return self.polynomial.challenge(kappa=self.kappa)

    def honest_func(self):
        return self.cypari.Pol("1")

    def func_open(self) -> list:
        """
        f is a polynomial consisting of the difference of two small challenges.
        This will guaranteed have an l_inf norm of at most 2.
        """
        c1: cypari2.Gen = self.get_challenge()
        c2: cypari2.Gen = self.get_challenge()
        if self.cypari(c1 == c2):
            c1 = self.get_challenge()
        return self.cypari(c2 - c1)

    def commit(self, c: Commit) -> list[cypari2.gen.Gen]:
        Ar, zerox = self.__a_with_message(c)
        return self.cypari(Ar + zerox)

    def open(self, open: CommitOpen) -> bool:
        Ar, zerox = self.__a_with_message(open)
        fz = open.f * zerox

        rhs = self.cypari(Ar + fz)
        lhs = self.cypari(open.f * open.c)
        return bool(self.cypari(lhs == rhs))

    def get_commit(self) -> tuple[Commit, list]:
        """
        Helper function to return a Commit with a random m, r as well as
        c from committing.
        """
        commit = Commit(
            m=self.polynomial.uniform_array(self.l), r=self.r_commit()
        )
        c = self.commit(commit)
        return commit, c


if __name__ == "__main__":
    start = time.time()
    comm = CommitmentScheme()
    open = dict()
    for i in range(100):
        c: Commit = Commit(
            m=comm.polynomial.uniform_array(comm.l), r=comm.r_commit()
        )
        commit = comm.commit(c)
        fun = comm.honest_func()
        opened = comm.open(CommitOpen(commit, fun, commit=c))
        open[opened] = open.get(opened, 0) + 1
    print(open)
    print("Total execution time: %s seconds" % (round(time.time() - start, 4)))