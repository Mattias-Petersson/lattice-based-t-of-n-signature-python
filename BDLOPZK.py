import math
from CommitmentSchemePoly import CommitmentScheme
import numpy as np
from Distributions import sampleGaussian, sampleUniform

from polynomial import Polynomial, convert2dToPoly, convert3dToPoly


class BDLOPZK:

    def __init__(self, B):
        self.cs = B

    def proofOfOpening(self, r):
        y = convert2dToPoly(sampleGaussian(self.cs.k, self.cs.N, self.cs.sigma, self.cs.q), self.cs.N, self.cs.q)
        t = np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), y)
        #d = sampleUniform(1, 0, 1, self.cs.q) #This should be a hash of t, r and A1
        #d = Polynomial(self.cs.N, self.cs.q, self.cs.getChallenge())
        d = np.zeros(self.cs.N)
        d[0] = 1
        d = Polynomial(self.cs.N, self.cs.q, d)
        dr = r
        for i in range(len(dr)):
            dr[i] = d * dr[i]
        z = y + dr
        #TODO: THIS SHOULD WOULD BE THE SAME, RIGHT????
        print("test distributive")
        print(np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), y) + np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), dr))
        print(np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), z))
        return (z, t, d)
    
    def checkProofOfOpening(self, c1, z, t, d):
        bound = 2* self.cs.sigma * np.sqrt(self.cs.N)
        for i in range(self.cs.k):
            if not z[i].isBounded(bound):
                print("zedcheck failure")
                return False
        lhs = np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), z)
        rhs = (t + (d * c1))
        print("lhs: ", lhs)
        print("rhs: ", rhs)
        for i in range(len(lhs)):
            if lhs[i] != rhs[i] :
                print("difference between: ", lhs[i], " and: ", rhs[i])
                return False
        return True
    

def main():
    B = CommitmentScheme()
    ZK = BDLOPZK(B)
    l = B.l
    #print("A1: ", B.A1)
    #print("A2: ", B.A2)

    message = Polynomial(B.N, B.q, sampleUniform(B.N, (B.q-1)/2, (B.q-1)/2, B.q))
    testProof = dict()
    for _ in range(1):
        randomness = B.getRCommit()
        com = B.commit(message, randomness)
        #print("Commitment: \n", com, "\n")
        opening = B.open(com, convert2dToPoly(randomness, B.N, B.q), message, Polynomial(B.N, B.q, B.getF(True)))
        #print("Open: \n", opening)
        d = np.zeros(B.N)
        d[0] = 1
        d = Polynomial(B.N, B.q, d)
        #TODO: THIS SHOULD ALSO BE THE SAME
        print("test dc1 = a1dr")
        print(d*com[0])
        dr = convert2dToPoly(randomness, B.N, B.q)
        for i in range(len(dr)):
            dr[i] = d * dr[i]
        print(np.matmul(convert3dToPoly(B.A1, B.N, B.q), dr))
        proof = ZK.proofOfOpening(convert2dToPoly(randomness, B.N, B.q))
        validity = ZK.checkProofOfOpening(com[0], *proof)
        print(validity)
        testProof[validity] = testProof.get(validity, 0) + 1
        #testy = sampleGaussian(B.k, np.zeros(B.k),B.sigma, B.q)
    print("Accuracy: ", testProof)
    
if __name__ == "__main__":
    main()