#Security parameter
sec = 0

#Noise Bound
Bdec = 0

#encrypt a message with a BGV public key, pk public key, ptx plaintext
def encBGV(pk, ptx):
    return 0

#decrypt a message with a BGV private key, sk secret key, ctx ciphertext
def decBGV(sk, ctx):
    return 0

#threshold decrypt a message with a BGV private key, ctx ciphertext, sk secret key share, U set of users
def tdecBGV(ctx, sk, U):
    return 0

#combine decryption shares created by tdec to generate a plaintext
def combBGV(ctx, DS):
    return 0

#compute new ciphertext from list of ciphertexts, F homomorphic function, CTX list of ciphertexts and encryption proofs
def evalBGV(F, CTX):
    return 0
