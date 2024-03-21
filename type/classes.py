from collections import namedtuple

type TN = tuple[int, int]


class Commit:
    """
    A commit consisting of a message m and a randomness r.
    """

    def __init__(self, m, r):
        self.m = m
        self.r = r


class CommitOpen(Commit):
    """
    To open a commit, we require a commitment c, a function f, and a commit.
    The commit can either be supplied by giving r & m direct, or as a Commit
    type.
    """

    def __init__(self, c, commit: Commit | None = None, f=None, m=None, r=None):
        if commit is None and m is None and r is None:
            raise ValueError("Either a commit or m & r needs to be supplied.")
        self.f = f if f else 1
        self.c = c

        if commit:
            super().__init__(commit.m, commit.r)
        else:
            super().__init__(m, r)


class ProofOfOpen:
    def __init__(self, z, t):
        self.z, self.t = z, t


class ProofOfSpecificOpen:
    def __init__(self, z, t1, t2):
        self.z, self.t1, self.t2 = z, t1, t2


class ProofOfOpenLinear(ProofOfOpen):
    def __init__(self, c, g, z=None, t=None, proof: ProofOfOpen | None = None):
        if proof is None and z is None and t is None:
            raise ValueError("Either a proof or z & t needs to be supplied.")
        self.c, self.g = c, g
        if proof:
            super().__init__(proof.z, proof.t)
        else:
            super().__init__(z, t)


SecretSharePoly = namedtuple("SecretShare", ["x", "p"])
NameData = namedtuple("NameData", ["name", "data"])
