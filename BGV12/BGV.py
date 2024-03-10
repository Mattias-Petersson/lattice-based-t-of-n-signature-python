from BDLOP16.BDLOP import BDLOP
from BDLOP16.CommitmentScheme import CommitmentScheme
from BDLOP16.RelationProofs import RelationProver
from BGV12.BGVParticipant import BGVParticipant
from SecretShare import SecretShare


class BGV:
    def __init__(
        self, comm_scheme, ZK, SSS, RP, n=4, t=2, q=2**32 - 527, N=1024
    ):
        self.participants = []
        self.comm_scheme = comm_scheme
        self.ZK = ZK
        self.SSS = SSS
        self.RP = RP
        for i in range(n):
            self.participants.append(
                BGVParticipant(
                    t,
                    n,
                    0,
                    2029,
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
    for p in self.participants:
        hbj.append(p.step2(haj, aj))
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
            p.step4(comsj, comej, comsjk, comejk, bj, bjk, proof_sk, sk, psk)
        )
    print(bool(self.comm_scheme.polynomial.cypari(step4[0][0] == step4[1][0])))
    print(bool(self.comm_scheme.polynomial.cypari(step4[0][1] == step4[1][1])))
    for i in range(len(step4[0][2])):
        print(
            bool(
                self.comm_scheme.polynomial.cypari(
                    step4[0][2][i] == step4[1][2][i]
                )
            )
        )
    return step4[0]
