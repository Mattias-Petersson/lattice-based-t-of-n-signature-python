from collections import namedtuple
import cypari2

type TN = tuple[int, int]
type poly = cypari2.gen.Gen


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

    def __add__(self, val):
        return ProofOfOpen(self.z + val.z, self.t + val.t)


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


class Ctx:
    def __init__(self, u, v, proof):
        self.u, self.v, self.proof = u, v, proof

    def __add__(self, other: "Ctx") -> "Ctx":
        return Ctx(self.u + other.u, self.v + other.v, None)

    def __mul__(self, n: poly) -> "Ctx":
        return Ctx(self.u * n, self.v * n, None)

    def __eq__(self, other: "Ctx"):
        return self.u == other.u and self.v == other.v

    def __hash__(self):
        return hash((str(self.u), str(self.v)))

    def verify(self, RP, a, b, p):
        return RP.verify_enc(a, b, p, self.u, self.v, *self.proof)

    __rmul__ = __mul__


SecretSharePoly = namedtuple("SecretShare", ["x", "p"])
NameData = namedtuple("NameData", ["name", "data"])
BgvSk = namedtuple("BgvSk", ["x", "commit"])
BgvPk = namedtuple("BgvPk", ["a", "b", "commits"])
BGVValues = namedtuple(
    "BGVValues", ["participants", "comm_scheme", "secret_share", "tn"]
)
GksPk = namedtuple("GksPk", ["a", "y"])
Signature = namedtuple("Signature", ["c", "z", "rho"])
