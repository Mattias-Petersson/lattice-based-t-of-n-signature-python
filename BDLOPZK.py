import math
from BasicFunctions import sampleGaussian, sampleUniform
from CommitmentScheme import CommitmentScheme
import numpy as np


class BDLOPZK:

    def __init__(self, B):
        self.cs = B

    def proofOfOpening(self, r):
        y = sampleGaussian(self.cs.k, np.zeros(self.cs.k), self.cs.sigma, self.cs.q)
        t = np.matmul(self.cs.A1, y)
        d = sampleUniform(1, 0, 1, self.cs.q) #This should be a hash of t, r and A1
        #d = self.cs.getChallenge()
        print("Y: ", y)
        z = (y + (d * r)) % self.cs.q
        print("Z: ", z)
        print("R: ", r)
        print("D: ", d)
        return (z, t, d)
    
    def checkProofOfOpening(self, c1, z, t, d):
        bound = 2* self.cs.sigma * np.sqrt(self.cs.N)
        for i in range(self.cs.k):
            if math.sqrt(z[i]) > bound and math.sqrt(z[i]) < self.cs.q - bound: 
                print("Zedcheck failure")
                return False
        comp1 = np.matmul(self.cs.A1, z) % self.cs.q
        comp2 = (t + d * c1) % self.cs.q
        print(comp1)
        print(comp2)
        for i in range(len(comp1)):
            if comp1[i]% self.cs.q != comp2[i] % self.cs.q :
                print((comp1[i] - comp2[i]))
                return False
            else:
                print("hi")
        return True
    

def main():
    B = CommitmentScheme()
    ZK = BDLOPZK(B)
    l = B.l
    #print("A1: ", B.A1)
    #print("A2: ", B.A2)
    message = np.array([1], ndmin=l)
    testProof = dict()
    for _ in range(100):
        randomness = B.getRCommit()
        com = B.commit(message, randomness)
        #print("Commitment: \n", com, "\n")
        opening = B.open(com, randomness, message, [1])
        #print("Open: \n", opening)
        proof = ZK.proofOfOpening(randomness)
        print("C: ", com)
        print("R: ", randomness)
        """
        print("d * (A1 r): ", np.matmul([1], np.matmul(B.A1, randomness)))
        print("A1 (d * r): ", np.matmul(B.A1, 1 * randomness))
        print([np.matmul([1], np.matmul(B.A1, randomness))] - np.matmul(B.A1, 1 * randomness))
        """
        validity = ZK.checkProofOfOpening(com[0], *proof)
        print(validity)
        testProof[validity] = testProof.get(validity, 0) + 1
        testy = sampleGaussian(B.k, np.zeros(B.k),B.sigma, B.q)
    print("Accuracy: ", testProof)
    ##TODO: Figure this shit out, lmao. Page 11 BDLOP16
    #print(np.matmul(np.transpose(B.A1), (testy + (proof[2]) * randomness))[0] % B.q)
    #print(np.matmul(np.transpose(B.A1), testy) + (proof[2]) * com[0])
    a1 = ((np.matmul(B.A1, testy) +  np.matmul(B.A1, 1 * randomness)[0]) % B.q)
    #print(a1)
    a2 = ((np.matmul(B.A1, (testy + (1 * randomness)))[0]) % B.q)
    #print(a2)
    #print("Diff: ", a2 - a1)
    #print(np.matmul(np.transpose(B.A1),  proof[2] * randomness))
    """ A1(y + d * r) = A1 * y + A1 * d * r = A1 * y + d * (A1*r) = A1 * y + d * c1
    
    """
if __name__ == "__main__":
    main()