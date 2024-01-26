import numpy as np


#Returns an element of a polynomial Ring, sampled uniformly
def sampleUniform(Bound, v, sigma):
    return 0

#Returns an element of a polynomial Ring, sampled from a gaussian distribution
def sampleGaussian(N, v, sigma):
    mean = v
    cov = np.diag(np.ones(N)*sigma)
    return np.random.default_rng().multivariate_normal(mean, cov).T

#sample randomness
def sampleRandomness():
    return 0

#Hashes a ring element
def hashElement():
    return 0

#sums and array of ring elements
def sumElements():
    return 0

#multiply two elements of a polynomial ring
def multiplyElements():
    return 0

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
def innerProduct():
    return 0

#verify that a ring element is bounded
def checkBounded():
    return 0
