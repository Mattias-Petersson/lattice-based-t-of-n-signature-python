import numpy as np
from BDLOP16.BDLOP import BDLOP
from BDLOP16.BDLOPCommScheme import BDLOPCommScheme
from BDLOP16.RelationProofs import RelationProver
from BGV12.BGVParticipant import BGVParticipant
from SecretSharing.SecretShare import SecretShare
from utils.Polynomial import Polynomial


class BGV:
    def __init__(
        self, comm_scheme, ZK, SSS, RP, n=4, t=2, q=2**32 - 527, N=1024, p=2029
    ):
        self.participants: list[BGVParticipant] = []
        self.comm_scheme = comm_scheme
        self.ZK = ZK
        self.SSS = SSS
        self.RP = RP
        self.t = 2
        self.p = p
        self.q = q
        for i in range(1, n + 1):
            self.participants.append(
                BGVParticipant(
                    t,
                    n,
                    0,
                    p,
                    q,
                    N,
                    i,
                    comm_scheme,
                    RP,
                    SSS,
                    comm_scheme.cypari,
                )
            )

    def keyGen(self):
        step1 = []
        for p in self.participants:
            step1.append(p.step1())
        haj = []
        aj = []
        for i in step1:
            haj.append(i[0])
            aj.append(i[1])
        hbj = []
        self.sprime = 0
        for p in self.participants:
            temp = p.step2(haj, aj)
            hbj.append(temp[0])
            self.sprime += temp[1]
        step3 = []
        for p in self.participants:
            step3.append(p.step3(hbj))
        comsj = []
        comej = []
        comsjk = []
        comejk = []
        bj = []
        bjk = []
        proof_sk = []
        sjk = []
        psjk = []
        for i in step3:
            comsj.append(i[0])
            comej.append(i[1])
            comsjk.append(i[2])
            comejk.append(i[3])
            bj.append(i[4])
            bjk.append(i[5])
            proof_sk.append(i[6])
            sjk.append(i[7])
            psjk.append(i[8])
        self.bs = bj
        step4 = []
        for i in range(len(self.participants)):
            p = self.participants[i]
            comek = []
            bk = []
            comsk = []
            sk = []
            psk = []
            for j in range(len(self.participants)):
                comsk.append(comsjk[j][i])
                bk.append(bjk[j][i])
                comek.append(comejk[j][i])
                sk.append(sjk[j][i])
                psk.append(psjk[j][i])
            step4.append(
                p.step4(
                    comsj, comej, comsjk, comejk, bj, bjk, proof_sk, sk, psk
                )
            )
        print(
            bool(self.comm_scheme.polynomial.cypari(step4[0][0] == step4[1][0]))
        )
        print(
            bool(self.comm_scheme.polynomial.cypari(step4[0][1] == step4[1][1]))
        )
        for i in range(len(step4[0][2])):
            print(
                bool(
                    self.comm_scheme.polynomial.cypari(
                        step4[0][2][i] == step4[1][2][i]
                    )
                )
            )
        return step4[0]

    def TDKGen(self):
        haj = []
        aj = []
        for p in self.participants:
            temp = p.step5()
            haj.append(temp[0])
            aj.append(temp[1])
        hyj = []
        for p in self.participants:
            hyj.append(p.step6(aj, haj))
        yj = []
        ctxj = []
        for p in self.participants:
            temp = p.step7(hyj)
            yj.append(temp[0])
            ctxj.append(temp[1])
        for p in self.participants:
            p.step8(yj, ctxj)

    def testTDkeys(self):
        works = True
        for i in range(len(self.participants)):
            for j in range(len(self.participants)):
                if self.participants[i].pkts[0] != self.participants[j].pkts[0]:
                    works = False
                if self.participants[i].pkts[1] != self.participants[j].pkts[1]:
                    works = False
        print(works)

    def sign(self, m, U):
        wj = []
        ctx_r = []
        for i in U:
            temp = self.participants[i].signStep1()
            wj.append(temp[0])
            ctx_r.append(temp[1])
        ret = []
        for i in U:
            ret.append(
                self.participants[i].signStep2(
                    wj, ctx_r, m, [U[0] + 1, U[1] + 1]
                )
            )
        ds_j = []
        for i in range(len(U)):
            temp = []
            for j in range(len(U)):
                temp.append(ret[j][i])
            ds_j.append(temp)
        res = []
        for i in U:
            res.append(self.participants[i].signStep3(ds_j))
        print("MAJOR TEST")
        print(res[0][0] == res[1][0])
        print(res[0][1][0] == res[1][1][0])
        print(res[0][1][1] == res[1][1][1])
        return res[0]

    def run(self):
        self.keyGen()
        PH = Polynomial(1024, self.p)
        PHq = Polynomial(1024, self.q)
        m = PHq.in_rq(PHq.in_rq("1"))
        m2 = PHq.in_rq(PHq.in_rq("1"))
        print(m)
        enc = self.participants[0].enc(m)
        enc2 = self.participants[0].enc(m2)
        add_enc = self.participants[0].add_ctx(enc, enc2)
        mul_enc = self.participants[0].mult_ctx(
            self.comm_scheme.cypari.Pol("x^2+2"), enc2
        )
        t_decs = []
        for i in range(0, self.t):
            t_decs.append(
                self.participants[i].t_dec(*add_enc, range(1, self.t + 1))
            )
        ptx = PH.in_rq(self.participants[0].comb(add_enc[1], t_decs))
        t_decs2 = []
        for i in range(0, self.t):
            t_decs2.append(
                self.participants[i].t_dec(*mul_enc, range(1, self.t + 1))
            )
        ptx2 = PH.in_rq(self.participants[0].comb(mul_enc[1], t_decs2))
        self.TDKGen()
        self.testTDkeys()
        sign = self.sign(m, [0, 1])
        print(self.participants[0].verify(sign[0], sign[1], m))
        print(ptx)
        print(ptx2)
        return bool(m + m2 == ptx)


c = BDLOPCommScheme()
zk = BDLOP(c)
s = SecretShare((2, 4), 2**32 - 527)
r = RelationProver(zk, c, s)
bgv = BGV(c, zk, s, r)
print(bgv.run())
