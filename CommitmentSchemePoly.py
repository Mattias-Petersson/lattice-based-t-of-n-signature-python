import math
import numpy as np
from Distributions import sampleUniform
import numpy.linalg as lin

from polynomial import Polynomial, convert2dToPoly, convert3dToPoly



class CommitmentScheme:
    """
    A basic commitment scheme. q is chosen such that q = 2d + 1 mod (4d), 
    with d = 8. q is also set to be a prime approximately equal to 2^32.
    All params are over R_q. 

    :param l int: Dimension of the message space.
    :param k int: Width of the commitment matrices.
    :param n int: Height of the commitment matrix A1.
    :param q int: Prime modulus defining R_q. 
    """

    def __init__(self, l: int = 1, k: int = 3, n: int = 1, q: int = 2 ** 32 - 527):
        def __makeA1(self):
            A1prime = sampleUniform((n, k-n, self.N), *self.uniformValues)
            ident = __makeIdentity3d(self, (np.identity(n)))
            return np.concatenate([ident, A1prime], axis=1)

        def __makeA2(self):
            A2prime = sampleUniform((l, k-n-l, self.N), *self.uniformValues)
            return np.concatenate([np.zeros((l, n, self.N)), __makeIdentity3d(self, np.identity(l)), A2prime], axis=1)
        
        def __makeIdentity3d(self, ident):
            ident3d = np.zeros((len(ident), len(ident), self.N))
            
            for i in range(len(ident)):
                for j in range(len(ident[0])):
                    if ident[i][j] == 1:
                        ident3d[i][j] = np.zeros(self.N)
                        ident3d[i][j][0] = 1
                    else:
                        ident3d[i][j] = np.zeros(self.N)
            return ident3d
 

        self.l = l
        self.k = k
        self.q = q
        self.n = n
        self.uniformValues = ((q-1)/2, (q-1)/2, q)
        self.N = 1024
        self.kappa = 36
        self.sigma = math.floor(11 * self.kappa * 1 *
                                math.sqrt(self.k * self.N))
        self.A1 = __makeA1(self)
        self.A2 = __makeA2(self)
        self.A1A2 = np.concatenate((self.A1, self.A2))

    def __str__(self):
        return "A: " + str(self.A1A2)

    def getRCommit(self): #-> np.ndarray[Any, Any]:
        """
        Generate a random polynomial vector bounded by S_{beta} of length k.
        """
        #TODO: This should create a length k vector of polynomials (power N), currently only creates 1 polynomial
        r1 = np.random.randint(-1, 2, size=self.N)
        while lin.norm(r1, np.inf) == 0:  # In case we get an all zero vector.
            r1 = np.random.randint(-1, 2, size=self.N)
        r2 = np.random.randint(-1, 2, size=self.N)
        while lin.norm(r2, np.inf) == 0:  # In case we get an all zero vector.
            r2 = np.random.randint(-1, 2, size=self.N)
        r3 = np.random.randint(-1, 2, size=self.N)
        while lin.norm(r3, np.inf) == 0:  # In case we get an all zero vector.
            r3 = np.random.randint(-1, 2, size=self.N)
    
        return [r1, r2, r3]

    """def getROpen(self) -> np.ndarray:
        bound = math.floor(4 * self.sigma * math.sqrt(self.N))
        r = np.random.randint(-bound, bound, size=self.k)
        while (lin.norm(r, 2) <= bound or lin.norm(r, 2) == 0):
            r = np.random.randint(-bound, bound, size=self.k)
        return np.reshape(r, (self.k, 1))"""

    def getF(self, honest):
        if honest:
            poly = np.zeros(self.N)
            poly[0] = 1
            return poly
        c1 = self.getChallenge()
        c2 = self.getChallenge()
        while (np.array_equal(c1, c2)):
            c1 = self.getChallenge()
        cDiff = np.subtract(c1, c2)
        print("C is invertible in R_q:", lin.norm(cDiff, np.inf) <= 2)
        return cDiff

    def getChallenge(self):
        """
        We need a challenge in the ring R_q, with an l_inf norm of 1, 
        and a l_1 norm of kappa.
        """
        remainingOnes = self.kappa
        c = np.zeros(self.N)
        while (remainingOnes > 0):
            idx = np.random.randint(len(c))
            if (c[idx]) == 0:
                c[idx] = np.random.choice([-1, 1])
                remainingOnes -= 1
        return c

    def commit(self, x, r):
        Ar = np.matmul(convert3dToPoly(self.A1A2, self.N, self.q), convert2dToPoly(r, self.N, self.q))
        zerox = np.vstack((np.array([convert2dToPoly(np.zeros((self.n, self.N)), self.N, self.q)]), np.array([x])))
        for i in range(2):
            Ar[i] = Ar[i] + zerox[i][0]
        return Ar

    def open(self, C, r, x, f):
        """
        f * C = A1A2 * r + F * ZeroX
        """
        lhs = C
        for i in range(len(lhs)):
                lhs[i] = f * lhs[i]

        Ar = convert3dToPoly(self.A1A2, self.N, self.q)
        Ar = np.matmul(Ar, r)
        zerox = np.array([Polynomial(self.N, self.q), x])
        fz = zerox
        for i in range(len(fz)):
            fz[i] = f * fz[i]
        rhs = np.add(Ar, fz)
        for i in range(len(lhs)):
            if not (np.array_equal(lhs[i].arr, rhs[i].arr)):
                print("lhs rhs not equals \n lhs: ", lhs[i].arr, "\n rhs: ", rhs[i].arr, "\n at: i: (", i, ")")
                return False
        return True

    def open2(self, C, r, x, f):
        c1c2 = np.reshape(C, (2, 1))
        lhs = f * c1c2 % self.q
        c1f = np.dot(C[0], f) % self.q
        Ar = np.matmul(self.A1A2, r) % self.q

        print("A1r:", Ar[0], "\n c1f:", c1f)
        print(Ar[0] == c1f)
        zerox = np.reshape(np.concatenate((np.zeros(self.n), x)), (2, 1))
        fZerox = f * zerox
        # rhs = np.add(Ar, fZerox) % self.q
        # print("LHS: ", lhs % self.q, lhs.shape)
        # print("RHS:", rhs % self.q, rhs.shape)
        # return np.array_equal(lhs % self.q, rhs % self.q)
        # lhs = np.matmul(f, np.reshape(C, (2, 1))) % self.q


def works():
    """
    Also, if an (honest) committer would like to simply open the commitment (without
    giving a zero-knowledge proof), he can simply output the r, x from (7) and f = 1.
    """
    m = Polynomial(1024, 2 ** 32 - 527, np.zeros(1024))#np.random.randint(C.q, size=C.l)
    rCommit = C.getRCommit()
    #rOpen = C.getROpen()
    #randomR = [rCommit, rOpen]
    #idx = np.random.randint(2)
    c2 = C.commit(m, rCommit)
    open = C.open(c2, convert2dToPoly(rCommit, C.N, C.q), m, Polynomial(C.N, C.q, C.getF(True)))
    return open

"""
def doesntWork():
    m = np.random.randint(C.q, size=C.l)
    rCommit = C.getRCommit()
    rOpen = C.getROpen()
    c2 = C.commit(m, rCommit)
    open = C.open(c2, rCommit, m, [1])
    return open
"""
if __name__ == "__main__":
    C = CommitmentScheme()
    counts = dict()
    for _ in range(10):
        # open = doesntWork()
        open = works()
        counts[open] = counts.get(open, 0) + 1
    print(counts)
