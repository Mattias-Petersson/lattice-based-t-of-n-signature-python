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
        print("y bounded :", y[0].isBounded(2* self.cs.sigma * np.sqrt(self.cs.N)), y[1].isBounded(2* self.cs.sigma * np.sqrt(self.cs.N)), y[2].isBounded(2* self.cs.sigma * np.sqrt(self.cs.N)))
        t = np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), y)
        #d = sampleUniform(1, 0, 1, self.cs.q) #This should be a hash of t, r and A1
        #d = Polynomial(self.cs.N, self.cs.q, self.cs.getChallenge())
        d = np.zeros(self.cs.N)
        d[1] = 1
        d = Polynomial(self.cs.N, self.cs.q, d)
        print("Y: ", y)
        print("T", t)
        dr = r
        for i in range(len(dr)):
            dr[i] = d * dr[i]
        print("D*R: ", dr)

        z = y + dr
        print("Z: ", z)
        print("R: ", r)
        print("D: ", d)
        return (z, t, d)
    
    def checkProofOfOpening(self, c1, z, t, d):
        bound = 2* self.cs.sigma * np.sqrt(self.cs.N)
        for i in range(self.cs.k):
            if not z[i].isBounded(bound):
                print("zedcheck failure")
                return False
        lhs = np.matmul(convert3dToPoly(self.cs.A1, self.cs.N, self.cs.q), z)
        rhs = (t + (d * c1))
        print("DC1: ", (d * c1))
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
    print(message)
    testProof = dict()
    for _ in range(1):
        randomness = B.getRCommit()
        com = B.commit(message, randomness)
        #print("Commitment: \n", com, "\n")
        opening = B.open(com, convert2dToPoly(randomness, B.N, B.q), message, Polynomial(B.N, B.q, B.getF(True)))
        #print("Open: \n", opening)
        d = np.zeros(B.N)
        d[1] = 1
        d = Polynomial(B.N, B.q, d)
        proof = ZK.proofOfOpening(convert2dToPoly(randomness, B.N, B.q))
        print("dC: ", d * com[0])
        dr = convert2dToPoly(randomness, B.N, B.q,)
        print("before: ", dr)
        for i in range(len(dr)):
            dr[i] = d * dr[i]
        print("after: ", dr)
        print("A1 * dR: ", np.matmul(convert3dToPoly(B.A1, B.N, B.q), dr))
        print("A1 * R: ", np.matmul(convert3dToPoly(B.A1, B.N, B.q), convert2dToPoly(randomness, B.N, B.q,)))
        """
        print("d * (A1 r): ", np.matmul([1], np.matmul(B.A1, randomness)))
        print("A1 (d * r): ", np.matmul(B.A1, 1 * randomness))
        print([np.matmul([1], np.matmul(B.A1, randomness))] - np.matmul(B.A1, 1 * randomness))
        """
        validity = ZK.checkProofOfOpening(com[0], *proof)
        print(validity)
        testProof[validity] = testProof.get(validity, 0) + 1
        #testy = sampleGaussian(B.k, np.zeros(B.k),B.sigma, B.q)
    print("Accuracy: ", testProof)
    ##TODO: Figure this shit out, lmao. Page 11 BDLOP16
    #print(np.matmul(np.transpose(B.A1), (testy + (proof[2]) * randomness))[0] % B.q)
    #print(np.matmul(np.transpose(B.A1), testy) + (proof[2]) * com[0])
    #a1 = ((np.matmul(B.A1, testy) +  np.matmul(B.A1, 1 * randomness)[0]) % B.q)
    #print(a1)
    #a2 = ((np.matmul(B.A1, (testy + (1 * randomness)))[0]) % B.q)
    #print(a2)
    #print("Diff: ", a2 - a1)
    #print(np.matmul(np.transpose(B.A1),  proof[2] * randomness))
    """ A1(y + d * r) = A1 * y + A1 * d * r = A1 * y + d * (A1*r) = A1 * y + d * c1
    
    """
if __name__ == "__main__":
    main()