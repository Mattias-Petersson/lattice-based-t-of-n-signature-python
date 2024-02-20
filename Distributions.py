import numpy as np


def sampleUniform(n: int |  tuple[int, int] | tuple[int, int, int], mean, sigma, q) -> np.ndarray:
    return np.random.randint(mean-sigma, mean+sigma+1, size=n) % q

def sampleGaussian(k, N, sigma, q):
    final = np.zeros((k,N))
    for i in range(k):
        for j in range(N):
            unrounded = np.random.normal(0, sigma) % q#(np.random.default_rng().multivariate_normal(mean, cov).T) % q
            final[i][j] = round(unrounded)
    return final



if __name__ == "__main__":
    q = 2 ** 32 - 527
    print(q)
    x = sampleUniform((5, 3, 2), (q-1)/2, (q-1)/2, q)
    print(x)
    print(x.shape)
