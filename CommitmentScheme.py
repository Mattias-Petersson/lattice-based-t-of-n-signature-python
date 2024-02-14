import numpy as np
from BasicFunctions import sampleUniform

type PP = tuple[np.ndarray, np.ndarray]


class CommitmentScheme:
    """
    A basic commitment scheme. q is chosen such that q = 2d + 1 mod (4d), 
    with d = 8. q is also set to be a prime approximately equal to 2^32.

    """

    def keyGen(self, l: int = 1, k: int = 3, q: int = 2 ^ 32 - 527, n: int = 1) -> PP:
        A1 = np.zeros((k, n))
        A2 = np.zeros((k, l))
        A1prime = np.zeros((k-n, n))
        A2prime = np.zeros((k-n-l, n))
        distributionValues = (n, (q-1)/2, (q-1)/2, q)
        """
        for i in range(0, k-n):
            A1prime[i] = sampleUniform(*(distributionValues))
        for i in range(0, k-n-l):
            A2prime[i] = sampleUniform(*(distributionValues))
        """
        for i in range(0, k-n-l):
            A1prime[i] = sampleUniform(*(distributionValues))
            A2prime[i] = sampleUniform(*(distributionValues))
        for i in range(k-n-l, k-n):
            A1prime[i] = sampleUniform(*(distributionValues))

        ident = np.identity(n)
        for i in range(0, n):
            A1[i] = ident[i]
        for i in range(n, k):
            A1[i] = A1prime[i-n]

        ident = np.identity(l)
        zer = np.zeros((l, n))
        for i in range(0, l):
            A2[i] = zer[i]
        for i in range(l, 2*l):
            A2[i] = ident[i-l]
        for i in range(2*l, k):
            A2[i] = A2prime[i-2*l]

        return (A1, A2)

    def commit(self):
        pass

    def open(self):
        pass


B = CommitmentScheme()

keys = B.keyGen()
print(keys[0], keys[1])
