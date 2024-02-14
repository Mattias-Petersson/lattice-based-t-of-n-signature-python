import numpy as np


#Returns an element of a polynomial Ring, sampled uniformly
def sampleUniform(N, mean, sigma, q):
    res = np.zeros(N)
    for i in range (0, N):
        res[i] = np.random.randint(mean-sigma, mean+sigma) % q
    return res

#Returns an element of a polynomial Ring, sampled from a gaussian distribution
def sampleGaussian(N, v, sigma, q):
    mean = v
    cov = np.diag(np.ones(N)*(sigma**2))
    return (round(np.random.default_rng().multivariate_normal(mean, cov).T) % q)

def sampleKnuth(P, r, q):
    d = 0
    r2 = r
    for col in range(0, len(P[0])):
        d = 2*d + (r2&1)
        r2 = r2 >> 1
        for row in range(0, len(P)):
            d = d - P[row][col]
            if d == -1:
                if(r2&1) == 1:
                    return q-row
                else:
                    return row
    return 0

#Hashes a ring element
def hashElement(x):
    return hash(tuple(x))

#sums and array of ring elements
def sumElements(x, y, q):
    N = len(x)
    res = np.zeros(N)
    for i in range(0, N-1):
        res[i] = (x[i] + y[i])%q
    return res[:N]

#multiply two elements of a polynomial ring
def multiplyElements(x, y, q):
    N = len(x)
    temp = np.zeros(N)
    for i in range(0, N):
        for j in range(0, N):
            temp[(i+j)%N] = (temp[(i+j)%N] + (x[i] * y[j]))%q
        print(temp)
    return temp

#commits a message according to a commitment scheme
def commit():
    return 0

#verify that a commitment is valid
def openCommitment():
    return 0

#shares an element of a ring according to t-out-of-n secret sharing
def secretShare():
    return 0

#reconstructs an element created with t-out-of-n secret sharing
def reconstructSecrets():
    return 0

#returns the inner product of 2 elements of a polynomial ring
def innerProduct(x, y, q):
    N = len(x)
    res = np.zeros(N)
    for i in range(0, N):
        res[i] = (x[i] * y[i])%q
    return res[:N]

#verify that a ring element is bounded
def checkBounded():
    return 0