#Security parameter
sec = 0

#Noise Bound
Bdec = 0

#i is the parties id, u is the number of parties
def BGVKeyGen(i, u, t, n, d):
    ai = sampleUniform()
    hai = hashElement(ai)
    #broadcast hai and ai
    As = receiveA()
    HAs = receiveHA()
    for(j in range(u)):
        if(j == i):
            continue
        if(hashElement(As[j]) != HAs[j])
            return -j
    a = sum(As)
    si = sampleGaussian()
    ei = sampleGaussian()
    bi = multiplyElements(a, si) + p * ei
    hbi = hashElement(bi)
    #broadcast hbi
    HBs = receiveHB()
    # psi, pei and psij + peij for each other j
    sharedSIs = secretShare(si)
    sharedEIs = secretShare(ei)
    sharedBIs = []
    for for(j in range(u)):
        if(j == i):
            continue
    #Loop adding a * shared sij + p * shared eij to BIs
    COMSIJs = []
    COMEIJs = []
    #Loops commiting for sij and eij
    SKproofs = []
        for(j in range(u)):
            skproof = proveSK()
    #broadcast commits, bi, bijs
    Bs = receiveB()
    BJs = receiveBJ()
    for(j in range(u)):
        if(j == i):
            continue
        if(hashElement(Bs[j]) != HBs[j])
            return -j
    for(j in range(u)):   
        if(reconstructSecrets(BJs[j]) != Bs[j]):
            return -j
        if(openCommitment() == 0):
            return -j
        if(verifySK() == 0):
            return -j
    b = sum(Bs)
    si = sum(sij)
    psi = sum(psij)
    comsk = sum(comsji)
    return {{a, b, comsk}, {si, psi}}






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
