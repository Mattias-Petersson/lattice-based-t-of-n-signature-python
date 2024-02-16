import math
from BasicFunctions import sampleGaussian, sampleUniform
from CommitmentScheme import CommitmentScheme
import numpy as np


class BDLOPZK:

    def __init__(self, B):
        self.cs = B

    def proofOfOpening(self, r):
        y = sampleGaussian(self.cs.k, np.zeros(self.cs.k), self.cs.sigma, self.cs.q)
        t = np.matmul(np.reshape(self.cs.A1, (1, 3)), np.reshape(y, (3, 1))) % self.cs.q
        d = sampleUniform(1, 0, 1, self.cs.q) #This should be a hash of t, r and A1
        print("Y: ", y)
        z = (y + d * r) % self.cs.q
        print("Z: ", z)
        print("R: ", r)
        print("D: ", d)
        for i in range(len(z)):
            temp = z[i]
            if temp > (self.cs.q-1)/2:
                temp = self.cs.q-temp
            print(math.sqrt(temp) / (self.cs.sigma * np.sqrt(self.cs.N)))
        return (z, t, d)
    
    def checkProofOfOpening(self, c1, z, t, d):
        bound = 2* self.cs.sigma * np.sqrt(self.cs.N)
        for i in range(self.cs.k):
            if math.sqrt(z[i]) > bound and math.sqrt(z[i]) < (-1 * bound) % self.cs.q:
                print("Zedcheck failure")
                return False
        comp1 = np.matmul(np.reshape(self.cs.A1, (1,3)), np.reshape(z, (3,1))) % self.cs.q
        comp2 = (t + d * c1) % self.cs.q
        for i in range(len(comp1)):
            for j in range(len(comp1[i])):
                if comp1[i][j] != comp2[i][j]:
                    return False
        return True
    

def main():
    B = CommitmentScheme()
    ZK = BDLOPZK(B)
    l = B.getL()
    message = np.array([1], ndmin=l)
    randomness = B.getR()
    com = B.commit(message, randomness)
    print("Commitment: \n", com, "\n")
    opening = B.open(com, randomness, message)
    print("Open: \n", opening)
    proof = ZK.proofOfOpening(randomness)
    print("C: ", com)
    validity = ZK.checkProofOfOpening(com[0], *proof)
    print(validity)

if __name__ == "__main__":
    main()