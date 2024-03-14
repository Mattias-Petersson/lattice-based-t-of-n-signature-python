import numpy as np
import cypari2
from BDLOP16.CommitmentScheme import CommitmentScheme
from type.classes import Commit, NameData


class Participant:
    def __init__(self, comm_scheme: CommitmentScheme):
        self.name = (
            np.random.choice(["Alice", "Bob"])
            + "_"
            + str(np.random.randint(1000))
        )
        self.p = 22
        self.comm_scheme = comm_scheme
        self.polynomial = self.comm_scheme.polynomial
        self.cypari = self.comm_scheme.cypari

        self.hashes: tuple[NameData, ...]
        self.other_a: tuple[NameData, ...]
        self.h_b: tuple[NameData, ...]

        self.hash = lambda x: self.polynomial.hash(self.comm_scheme.kappa, x)
        self.gaussian = lambda x: self.polynomial.gaussian_array(
            x, sigma=self.comm_scheme.sigma
        )

    def a_hash(self) -> NameData:
        self.a = self.polynomial.uniform_element()
        return NameData(self.name, self.hash(self.a))

    def own_a(self) -> NameData:
        return NameData(self.name, self.a)

    def compare_a_hash(self) -> NameData:
        for a in self.other_a:
            [hash_to_compare] = list(
                filter(lambda x: x.name == a.name, self.hashes)
            )

            if self.cypari(self.hash(a.data) != hash_to_compare.data):
                return NameData(a.name, False)
        return NameData(self.name, True)

    def make_b_i(self) -> NameData:
        """
        Runs compare_a_hash to ensure that the a's match with their hash.
        Then concatenates a to be the sum of all a_j, j from 0 to n.
        """
        self.sum_a = self.a
        for i in self.other_a:
            self.sum_a += i.data
        self.s_i, self.e_i = (self.gaussian(1) for _ in range(2))
        bi = self.cypari(self.sum_a * self.s_i + self.p * self.e_i)
        return NameData(self.name, self.hash(bi))

    def __commit(self, commitment):
        return self.comm_scheme.commit(
            Commit(commitment, self.comm_scheme.r_commit())
        )

    def step_three(self):
        com_si, com_ei = self.__commit(self.s_i), self.__commit(self.e_i)
