class Commit:
    def __init__(self, m, r):
        self.m = m
        self.r = r


class CommitOpen(Commit):
    def __init__(self, c, f, m=None, r=None, commit: Commit | None = None):
        if commit is None and m is None and r is None:
            raise ValueError("Either a commit or m & r needs to be supplied.")
        self.c, self.f = c, f
        if commit:
            super().__init__(commit.m, commit.r)
        else:
            super().__init__(m, r)


class ProofOfOpen:
    def __init__(self, z, t):
        self.z, self.t = z, t


class ProofOfOpenLinear(ProofOfOpen):
    def __init__(self, c, g, z=None, t=None, proof: ProofOfOpen | None = None):
        if proof is None and z is None and t is None:
            raise ValueError("Either a proof or z & t needs to be supplied.")
        self.c, self.g = c, g
        if proof:
            super().__init__(proof.z, proof.t)
        else:
            super().__init__(z, t)
