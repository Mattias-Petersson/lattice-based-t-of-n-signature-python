import numpy as np
from BasicFunctions import sampleUniform

type PP = tuple[np.ndarray, np.ndarray]


class CommitmentScheme:
    """
    A basic commitment scheme. q is chosen such that q = 2d + 1 mod (4d), 
    with d = 8. q is also set to be a prime approximately equal to 2^32.

    """

    def __init__(self, l: int = 1, k: int = 3, q: int = 2 ^ 32 - 527, n: int = 1):
        self.l = l
        self.k = k
        self.q = q
        self.n = n
        self.distributionValues = (n, (q-1)/2, (q-1)/2, q)

        self.A1 = np.zeros((k, n))
        self.A2 = np.zeros((k, l))
        A1prime = np.zeros((k-n, n))
        A2prime = np.zeros((k-n-l, n))

        for i in range(0, k-n-l):
            A1prime[i] = sampleUniform(*(self.distributionValues))
            A2prime[i] = sampleUniform(*(self.distributionValues))
        for i in range(k-n-l, k-n):
            A1prime[i] = sampleUniform(*(self.distributionValues))

        ident = np.identity(n)
        for i in range(0, n):
            self.A1[i] = ident[i]
        for i in range(n, k):
            self.A1[i] = A1prime[i-n]

        ident = np.identity(l)
        zer = np.zeros((l, n))
        for i in range(0, l):
            self.A2[i] = zer[i]
        for i in range(l, 2*l):
            self.A2[i] = ident[i-l]
        for i in range(2*l, k):
            self.A2[i] = A2prime[i-2*l]

    def __str__(self):
        return "A1: " + str(self.A1) + "\n A2: " + str(self.A2)

    def commit(self, x):
        """
        Commit to message x. 
        """
        dist = self.distributionValues
        r = sampleUniform(*(dist))
        C = np.concatenate((self.A1, self.A2))
        message = np.concatenate((np.zeros(self.n), x))
        C = np.matmul(C, r)
        C += message
        return C

    def open(self):
        pass


B = CommitmentScheme()

keys = B
print(B)
x = np.zeros(1)
print(B.commit(x))
