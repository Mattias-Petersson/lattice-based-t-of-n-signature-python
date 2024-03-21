from BDLOP16.BDLOP import BDLOP
from BDLOP16.CommitmentScheme import CommitmentScheme
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

    def run(self):
        self.keyGen()
        PH = Polynomial(1024, self.p)
        m = PH.in_rq(PH.uniform_array(1))
        enc = self.participants[0].enc(m)
        t_decs = []
        for i in range(0, self.t):
            t_decs.append(
                self.participants[i].t_dec(*enc, range(1, self.t + 1))
            )
        print(len(t_decs))
        sk = self.SSS.reconstruct_poly(
            [self.participants[0].ski[0], self.participants[3].ski[0]],
            [self.participants[0].i, self.participants[3].i],
        )
        ptx = PH.in_rq(self.participants[0].comb(enc[1], t_decs))
        ptx1 = PH.in_rq(self.participants[0].dec(*enc, sk))
        b = self.participants[0].pk[1]
        bsum = sum(self.bs)
        a = self.participants[0].pk[0]
        bprime = self.comm_scheme.cypari.liftall(
            b
        ) * self.comm_scheme.cypari.Mod(1, self.p)
        aprime = self.comm_scheme.cypari.liftall(
            a
        ) * self.comm_scheme.cypari.Mod(1, self.p)
        skprime = self.comm_scheme.cypari.liftall(
            sk
        ) * self.comm_scheme.cypari.Mod(1, self.p)
        print(skprime == self.sprime)
        print(PH.in_rq(aprime) * PH.in_rq(skprime) == PH.in_rq(bprime))
        print(b == bsum)
        print(m == ptx)
        print(m == ptx1)
        print(ptx1 == ptx)
        return bool(m == ptx)


c = CommitmentScheme()
zk = BDLOP(c)
s = SecretShare((2, 4), 2**32 - 527)
r = RelationProver(zk, c, s)
bgv = BGV(c, zk, s, r)
bgv.run()
