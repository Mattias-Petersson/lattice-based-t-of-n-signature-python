from sympy import *
import numpy as np
x, y, z = symbols('x,y,z')
init_printing(use_unicode=False, wrap_line=False)
N = 2048
q = 16801793
p = Poly(x**N + 1, modulus=q)
print(p.domain)
p2 = Poly(x**(N+2) + 1, modulus=q)
r = Poly(p2.rem(p), modulus=q)
print(r)

p3 = (Poly(-12288*x, modulus=q)  * (p - Poly(2*x**N, modulus=q)))
print(p3)
print(p3.rem(p))
import matplotlib.pyplot as plt
mean = np.zeros(N) +q/2
v = 14
cov = np.diag(np.ones(N))*(v*np.sqrt(N))**2
print(v*np.sqrt(N))
x = np.random.default_rng().multivariate_normal(mean, cov, 1).T
print(np.round(x))


plt.plot(x, range(0, N), 'x')
plt.axis('equal')
plt.show()