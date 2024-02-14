import numpy as np
from BasicFunctions import *

type PP = tuple[np.ndarray, np.ndarray]

class CommitmentScheme:
    """
    A basic commitment scheme. q is chosen such that q = 2d + 1 mod (4d), 
    with d = 8.
    
    """
    
    def keyGen(self, k, l, b, q: int = 2^32 - 527, n: int = 1) -> PP:
        A1prime = np.zeros((k-n, n))
        for i in range(0, k-n):
            A1prime[i] = sampleUniform(n, q-1/2, q-1/2, q)
        A2prime = np.zeros((k-n-l, n))
        for i in range(0, k-n-l):
            A2prime[i] = sampleUniform(n, q-1/2, q-1/2, q)
        A1 = np.concatenate(np.identity(n), A1prime)
        A2 = np.concatenate(np.zeros((l,n)), np.identity(l), A2prime)
        return (A1, A2)


    def commit(self):
        pass

    def open(self):
        pass
