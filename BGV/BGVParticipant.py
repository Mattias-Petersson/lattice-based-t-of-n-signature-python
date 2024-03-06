from BDLOP.CommitmentScheme import CommitmentScheme
from BDLOP.RelationProofs import RelationProver
from SecretShare import reconstruct_poly, share_poly
from type.classes import Commit, CommitOpen, ProofOfOpenLinear
from utils.Polynomial import Polynomial


class BGVParticipant:
    def __init__(
        self,
        t,
        n,
        d,
        p,
        q,
        N,
        i,
        comm_scheme: CommitmentScheme,
        RelationProofs: RelationProver,
        cypari,
    ):
        if i > n:
            raise ValueError()
        self.t = t  # Threshold
        self.n = n  # Participants
        self.d = d  #
        self.p = p  # prime much smaller than q
        self.q = q  # prime modulo
        self.N = N  # length of polynomials
        self.i = i
        self.PH = Polynomial(N, q)
        self.cypari = cypari
        self.comm_scheme = comm_scheme
        self.RP = RelationProofs

    def step1(self):
        ai = self.PH.uniform_array(1)
        hai = hash(ai)
        return (hai, ai)

    def step2(self, haj, aj):
        for i in range(len(haj)):
            if haj[i] != hash(aj[i]):
                raise RuntimeError(str(i))
        self.a = 0
        for i in aj:
            self.a = self.cypari(self.a + i)
        self.siprime = self.PH.gaussian_array(1, 1)
        self.eiprime = self.PH.gaussian_array(1, 1)
        self.bi = self.cypari(self.a * self.siprime + self.p * self.eiprime)
        hbi = hash(self.bi)
        return hbi

    def step3(self, hbj):
        self.hbj = hbj
        psiprime = self.comm_scheme.r_commit()
        peiprime = self.comm_scheme.r_commit()
        self.comsi = self.comm_scheme.commit(Commit(self.siprime, psiprime))
        self.comei = self.comm_scheme.commit(Commit(self.eiprime, peiprime))
        sij = share_poly(self.siprime, self.n, self.t, self.q)
        eij = share_poly(self.eiprime, self.n, self.t, self.q)
        psij = []
        peij = []
        comsij = []
        comeij = []
        bij = []
        for i in range(self.n):
            ps = self.comm_scheme.r_commit()
            pe = self.comm_scheme.r_commit()
            psij.append(ps)
            print(sij[i])
            comsij.append(self.comm_scheme.commit(Commit(sij[i], ps)))
            peij.append(pe)
            comeij.append(self.comm_scheme.commit(Commit(eij[i], pe)))
            bij.append(self.cypari(self.a * sij[i] + self.p * eij[i]))
        proof_sk = self.RP.prove_sk(psiprime, peiprime, psij, peij, self.a, self.p)
        return (
            self.comsi,
            self.comei,
            comsij,
            comeij,
            self.bi,
            bij,
            proof_sk,
            sij,
            psij,
        )

    def step4(
        self,
        comsj,
        comej,
        comsjk,
        comejk,
        bj,
        bjk,
        proofs_sk,
        sjk,
        psjk,
    ):
        for i in range(self.n):
            if i != self.i:
                if self.hbj[i] != hash(bj[i]):
                    raise RuntimeError(str(i) + " wrongHash")
                print(len(range(self.t)))
                print(len(bjk[i][: self.t]))
                if bj[i] != reconstruct_poly(bjk[: self.t][i], range(self.t)):
                    print("raise RuntimeError(str(i))")
                # if not self.comm_scheme.open(comsjk[i], sjk[i], psjk[i]):
                # raise RuntimeError(str(i))
                if not self.RP.verify_sk(
                    *(proofs_sk[i]),
                    bj[i],
                    bjk[i],
                    self.a,
                    self.p,
                    comsj[i],
                    comej[i],
                    comsjk[i],
                    comejk[i],
                ):
                    raise RuntimeError(str(i))

        b = 0
        si = 0
        psi = 0
        for i in range(self.n):
            b = self.cypari(b + bj[i])
            si = self.cypari(si + sjk[i][self.i])
            psi = self.cypari(psi + psjk[i][self.i])
        comsk = []
        for i in range(self.n):
            temp = 0
            for j in range(self.n):
                temp = self.cypari(
                    temp + comsjk[i][j]
                )  # this should maybe be [i][j], test if fails
            comsk.append(temp)
        print(len(comsk))
        self.pk = (self.a, b, comsk)
        self.ski = (si, psi)
        return self.pk
