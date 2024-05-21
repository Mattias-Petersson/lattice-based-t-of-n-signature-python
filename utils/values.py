default_values = {
    "q": 2**24 - 3,
    "p": 2**16 - 39,
    "N": 2**10,
    "tn": (6, 7),
    "sigma": 37640,
}

single_use_values = {
    "q": 2**20 - 5,
    "p": 2**16 - 39,
    "N": 2**10,
    "tn": (3, 6),
    "sigma": 2**11,
}
# Q is a large ciphertext modulus.
Q = 2**36 - 5
