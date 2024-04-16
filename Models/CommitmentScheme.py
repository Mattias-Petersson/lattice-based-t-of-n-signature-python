from abc import ABC, abstractmethod

from type.classes import Commit, CommitOpen
from utils.Polynomial import Polynomial
import cypari2


class CommitmentScheme(ABC):

    @abstractmethod
    def __init__(self, q: int, N: int, kappa: int):
        self.q = q
        self.N = N
        self.polynomial = Polynomial(self.q, self.N)
        self.cypari = self.polynomial.cypari

        """Kappa is the maximum l_1 norm to ensure small challenges. Sometimes
        referred to as Tau in documentation, we always call it kappa."""
        self.kappa = kappa

    @abstractmethod
    def r_commit(self):
        """
        Return randomness that can be used to commit to a message.
        """
        pass

    @abstractmethod
    def commit(self, commit: Commit) -> list[cypari2.gen.Gen]:
        pass

    @abstractmethod
    def open(self, commit_open: CommitOpen) -> bool:
        pass
