import math
import numpy as np
from BasicFunctions import sampleUniform

type PP = tuple[np.ndarray, np.ndarray]


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
            A1prime[i] = sampleUniform(*self.distributionValues)
            A2prime[i] = sampleUniform(*self.distributionValues)
        for i in range(k-n-l, k-n):
            A1prime[i] = sampleUniform(*self.distributionValues)

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

    def getL(self) -> int:
        return self.l

    def checkRandomness(self, randomness: np.ndarray) -> bool:
        """
        Ensures that the randomness selected is within allowed bounds.
        ___

        #TODO: Decide if this should be made private or not. 
        sigma = 11 * kappa * Beta * sqrt(k * N)
        """
        N = 1024
        sigma = 11 * 36 * 1 * math.sqrt(self.k * N)
        bound = 4 * sigma * math.sqrt(N)
        for i in randomness:
            if math.sqrt(np.sum(i)) > bound:
                return False
        return True

    def getR(self) -> np.ndarray:
        _, *dist = self.distributionValues
        allowedNorm = False
        randomness = np.zeros(self.k)
        while not allowedNorm:
            randomness = sampleUniform(self.k, *dist)
            allowedNorm = self.checkRandomness(randomness)
        return randomness

    def commit(self, message: np.ndarray, r: np.ndarray) -> np.ndarray:
        """
        Commit to a message with randomness r. 
        """
        C = np.transpose(np.hstack((self.A1, self.A2)))
        C = np.matmul(C, r)
        message = np.transpose(np.hstack((np.zeros(self.n), message)))
        return np.add(C, message)

    def open(self, C, r, message):
        Xtend = np.zeros(self.n + self.l)
        for i in range(self.n, self.n+self.l):
            Xtend[i] = message[i-self.n]
        f = 0
        while f is 0:
            f1 = sampleUniform(1, 0, 1, self.q)
            f2 = sampleUniform(1, 0, 1, self.q)
            f = np.subtract(f1, f2)
        print(f)
        A = np.hstack((self.A1, self.A2))
        Comp1 = np.matmul(np.transpose(A), r) + f * np.transpose(Xtend)
        Comp2 = f * C
        print(Comp1)
        print(Comp2)
        equals = True
        for i in range(len(Comp1)):
            if Comp1[i] != Comp2[i]:
                equals = False
        return equals


def main():
    B = CommitmentScheme()
    l = B.getL()
    message = np.array([1], ndmin=l)
    randomness = B.getR()
    com = B.commit(message, randomness)
    print("Commitment: \n", com, "\n")
    opening = B.open(com, randomness, message)
    print("Open: \n", opening)
    # B.commit(x)


if __name__ == "__main__":
    main()
