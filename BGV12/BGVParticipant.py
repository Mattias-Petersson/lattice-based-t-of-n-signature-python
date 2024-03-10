from BDLOP16.CommitmentScheme import CommitmentScheme
from BDLOP16.RelationProofs import RelationProver
from SecretShare import SecretShare
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
        SSS: SecretShare,
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
        self.SSS = SSS
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
        sij = self.SSS.share_poly(self.siprime)
        eij = self.SSS.share_poly(self.eiprime)
        psij = []
        peij = []
        comsij = []
        comeij = []
        bij = []
        for i in range(self.n):
            ps = self.comm_scheme.r_commit()
            pe = self.comm_scheme.r_commit()
            psij.append(ps)
            comsij.append(self.comm_scheme.commit(Commit(sij[i], ps)))
            peij.append(pe)
            comeij.append(self.comm_scheme.commit(Commit(eij[i], pe)))
            bij.append(self.cypari(self.a * sij[i] + self.p * eij[i]))
        proof_sk = self.RP.prove_sk(
            psiprime, peiprime, psij, peij, self.a, self.p
        )
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
                smaller_bjk = []
                for j in range(self.t):
                    smaller_bjk.append(bjk[i][j])
                if bj[i] != self.SSS.reconstruct_poly(
                    smaller_bjk, range(1, self.t + 1)
                ):
                    raise RuntimeError(str(i))
                if not self.comm_scheme.open(
                    CommitOpen(c=comsjk[i][self.i], f=1, m=sjk[i], r=psjk[i])
                ):
                    raise RuntimeError(str(i))
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
            si = self.cypari(si + sjk[i])
            psi = self.cypari(psi + psjk[i])
        comsk = []
        for i in range(self.n):
            temp = 0
            for j in range(self.n):
                temp = self.cypari(temp + comsjk[i][j])
            comsk.append(temp)
        self.b = b
        self.pk = (self.a, b, comsk)
        self.ski = (si, psi)
        return self.pk

    def enc(self, m):
        eprime = self.PH.gaussian_array(1, 1)
        ebis = self.PH.gaussian_array(1, 1)
        r = self.PH.gaussian_array(1, 1)
        peprime = self.comm_scheme.r_commit()
        pebis = self.comm_scheme.r_commit()
        pr = self.comm_scheme.r_commit()
        pm = self.comm_scheme.r_commit()
        com_eprime = self.comm_scheme.commit(Commit(eprime, peprime))
        com_ebis = self.comm_scheme.commit(Commit(ebis, pebis))
        com_r = self.comm_scheme.commit(Commit(r, pr))
        com_m = self.comm_scheme.commit(Commit(m, pm))
        u = self.comm_scheme.cypari(self.a * r + self.p * eprime)
        v = self.comm_scheme.cypari(self.b * r + self.p * ebis + m)
        proof_ctx = self.RP.prove_enc(
            pr, pm, peprime, pebis, self.a, self.b, self.p
        )
        return (u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis)

    def dec(self, u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis):
        if not self.RP.verify_enc(
            *proof_ctx,
            self.a,
            self.b,
            self.p,
            u,
            v,
            com_r,
            com_m,
            com_eprime,
            com_ebis,
        ):
            return 0
        ptx = self.cypari(v - self.ski[0] * u)
        return ptx

    def t_dec(self, u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis, U):
        lagrange = 0
        for j in U:
            if j != self.i:
                lagrange += j / (j - self.i)
        m_i = self.cypari(lagrange * self.ski[0] * u)
        E_i = self.PH.uniform_array(1)
        d_i = self.cypari(m_i + self.p * E_i)
        pE_i = self.comm_scheme.r_commit()
        com_Ei = self.comm_scheme.commit(Commit(E_i, pE_i))
        proof_dsi = 0  # TODO
        return (
            d_i,
            proof_dsi,
            com_Ei,
            self.comm_scheme.commit(Commit(*self.ski)),
        )

    def comb(self):
        raise RuntimeError("not implemented")
