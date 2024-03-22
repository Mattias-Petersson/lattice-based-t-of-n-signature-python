import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from BDLOP16.RelationProofs import RelationProver
from SecretSharing.SecretShare import SecretShare
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
            self.a = self.a + i
        self.siprime = self.PH.gaussian_array(1, 1)
        self.eiprime = self.PH.gaussian_array(1, 1)
        self.bi = self.a * self.siprime + self.p * self.eiprime
        hbi = hash(self.bi)
        return (hbi, self.siprime, self.bi)

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
            bij.append(self.a * sij[i] + self.p * eij[i])
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
        sji,
        psji,
    ):
        for j in range(self.n):
            if j != self.i - 1:
                if self.hbj[j] != hash(bj[j]):
                    raise RuntimeError(str(j) + " wrongHash")
                smaller_bjk = []
                for k in range(self.t):
                    smaller_bjk.append(bjk[j][k])
                if bj[j] != self.SSS.reconstruct_poly(
                    smaller_bjk, range(1, self.t + 1)
                ):
                    raise RuntimeError(str(j))
                if not self.comm_scheme.open(
                    CommitOpen(
                        c=comsjk[j][self.i - 1], f=1, m=sji[j], r=psji[j]
                    )
                ):
                    raise RuntimeError(str(j))
                if not self.RP.verify_sk(
                    *(proofs_sk[j]),
                    bj[j],
                    bjk[j],
                    self.a,
                    self.p,
                    comsj[j],
                    comej[j],
                    comsjk[j],
                    comejk[j],
                ):
                    raise RuntimeError(str(j))
        b = 0
        si = 0
        psi = 0
        for j in range(self.n):
            b = b + bj[j]
            si = si + sji[j]
            psi = psi + psji[j]
        comsk = []
        for i in range(self.n):
            temp = 0
            for j in range(self.n):
                temp = temp + comsjk[i][j]
            comsk.append(temp)
        self.b = b
        self.pk = (self.a, self.b, comsk)
        self.ski = (si, psi)
        return self.pk

    def step5(self):
        ai = self.PH.uniform_array(1)
        hai = hash(ai)
        return (hai, ai)

    def step6(self, aj, haj):
        a = 0
        for j in range(len(aj)):
            if hash(aj[j]) != haj:
                raise ValueError(j)
            a += aj[j]
        self.ats = [a, 1]
        si1 = self.PH.gaussian_array(1, 1)
        si2 = self.PH.gaussian_array(1, 1)
        self.si = [si1, si2]
        self.yi = [self.ats[0] * si1, si2]
        return hash(self.y)

    def step7(self, hyj):
        self.hyj = hyj
        ctx_si = [self.enc(self.si[0]), self.enc(self.si[1])]
        # TODO: proof_si
        return (self.yi, ctx_si)

    def step8(self, yj, ctx_sj):
        self.y = [0, 0]
        ctx_s = [0, 0]
        for j in range(len(yj)):
            if hash(yj[j]) != self.hyj[j]:
                raise ValueError(j)
            # TODO: verify proof_sj
            self.y = [self.y[0] + yj[j][0], self.y[1] + yj[j][1]]
            ctx_s = [ctx_s[0] + ctx_sj[j][0], ctx_s[1] + ctx_sj[j][1]]
        self.pkts = (self.ats, self.y)
        return self.pkts

    def enc(self, m):
        eprime = self.PH.gaussian_array(1, 1)
        ebis = self.PH.gaussian_array(1, 1)
        mprime = self.cypari.liftall(m) * self.cypari.Mod(1, self.q)
        r = self.PH.gaussian_array(1, 1)
        peprime = self.comm_scheme.r_commit()
        pebis = self.comm_scheme.r_commit()
        pr = self.comm_scheme.r_commit()
        pm = self.comm_scheme.r_commit()
        com_eprime = self.comm_scheme.commit(Commit(eprime, peprime))
        com_ebis = self.comm_scheme.commit(Commit(ebis, pebis))
        com_r = self.comm_scheme.commit(Commit(r, pr))
        com_m = self.comm_scheme.commit(Commit(mprime, pm))
        u = self.a * r + self.p * eprime
        v = self.b * r + self.p * ebis + mprime
        proof_ctx = self.RP.prove_enc(
            pr, pm, peprime, pebis, self.a, self.b, self.p
        )
        return (u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis)

    def dec(self, u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis, sk):
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
        ptx = v - sk * u
        ptx = self.cypari.liftall(
            ptx
            + self.cypari.Pol(
                self.cypari.round(np.ones(1024) * ((self.q - 1) / 2))
            )
        ) * self.cypari.Mod(1, self.p)
        ptx -= self.cypari.Pol(self.cypari.round(np.ones(1024) * (1958)))
        return ptx

    def t_dec(self, u, v, proof_ctx, com_r, com_m, com_eprime, com_ebis, U):
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
            print("fail")
            raise ValueError()
        lagrange = 1
        for j in U:
            if j != self.i:
                lagrange *= j * pow((j - self.i), self.q - 2, self.q)
        m_i = lagrange * self.ski[0] * u
        E_i = self.PH.uniform_array(1, 1)
        d_i = m_i + self.p * E_i
        pE_i = self.comm_scheme.r_commit()
        com_Ei = self.comm_scheme.commit(Commit(E_i, pE_i))
        proof_dsi = self.RP.prove_ds(self.ski[1], pE_i, u, lagrange, self.p)
        return (
            proof_dsi,
            self.comm_scheme.commit(Commit(self.ski[0], self.ski[1])),
            com_Ei,
            d_i,
        )

    def comb(self, v, t_decs):
        for i in t_decs:
            if not self.RP.verify_ds(*(i[0]), self.p, i[1], i[2], i[3]):
                raise ValueError
        sum_ds = 0
        for i in t_decs:
            sum_ds = sum_ds + i[3]
        ptx = self.cypari.liftall(
            v
            - sum_ds
            + self.cypari.Pol(
                self.cypari.round(np.ones(1024) * ((self.q - 1) / 2))
            )
        ) * self.cypari.Mod(1, self.p)
        ptx -= self.cypari.Pol(self.cypari.round(np.ones(1024) * (1958)))
        return ptx
