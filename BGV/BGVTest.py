from BDLOP.BDLOPZK import BDLOPZK
from BDLOP.CommitmentScheme import CommitmentScheme
from BDLOP.RelationProofs import RelationProver
from BGV.BGVParticipant import BGVParticipant


n = 4
t = 2
q = 2**32 - 527
N = 1024
participants = []
comm_scheme = CommitmentScheme()
ZK = BDLOPZK(comm_scheme)
RP = RelationProver(ZK, comm_scheme)
for i in range(n):
    participants.append(
        BGVParticipant(t, n, 0, 2029, q, N, i, comm_scheme, RP, comm_scheme.cypari)
    )
step1 = []
for p in participants:
    step1.append(p.step1())
haj = []
aj = []
for i in step1:
    haj.append(i[0])
    aj.append(i[1])
hbj = []
for p in participants:
    hbj.append(p.step2(haj, aj))
step3 = []
for p in participants:
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
for i in range(len(participants)):
    p = participants[i]
    comek = []
    bk = []
    comsk = []
    for j in range(len(participants)):
        comsk.append(comsjk[j][i])
        bk.append(bjk[j][i])
        comek.append(comejk[j][i])
    step4.append(p.step4(comsj, comej, comsjk, comejk, bj, bjk, proof_sk, sjk, psjk))
print(bool(comm_scheme.polynomial.cypari(step4[0][0] == step4[1][0])))
print(bool(comm_scheme.polynomial.cypari(step4[0][1] == step4[1][1])))
print(bool(comm_scheme.polynomial.cypari(step4[0][2][1] == step4[1][2][1])))
