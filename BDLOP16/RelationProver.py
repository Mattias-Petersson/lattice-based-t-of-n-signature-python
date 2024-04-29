from BDLOP16.BDLOP import BDLOP
from Models.CommitmentScheme import CommitmentScheme
from type.classes import Commit, ProofOfOpenLinear
from SecretSharing.SecretShare import SecretShare


class RelationProver:
    def __init__(
        self,
        ZK: BDLOP,
        comm_scheme: CommitmentScheme,
        secret_share: SecretShare,
    ):
        self.ZK = ZK
        self.comm_scheme = comm_scheme
        self.secret_share = secret_share
        self.r0 = [0 for _ in range(3)]

    def __commit_r0(self, x):
        return self.comm_scheme.commit(Commit(x, self.r0))

    def __commit_obj_r_com(self, *args) -> list[Commit]:
        return [Commit(i, self.comm_scheme.r_commit()) for i in args]

    def __make_proof_open_linear(self, *lst):
        return tuple[ProofOfOpenLinear, ...](
            ProofOfOpenLinear(c, g, proof=proof) for c, g, proof in lst
        )

    def __verify_sum(self, name, *args):
        if not self.ZK.verify_proof_of_sum(*args):
            raise ValueError(
                f"Failed to verify proof of sum for proof {name}:", *args
            )

    def __verify_triple_sum(self, name, *args):
        if not self.ZK.verify_proof_of_triple_sum(*args):
            raise ValueError(
                f"Failed to verify proof of triple sum for proof {name}:", *args
            )

    def __verify_open(self, name, *args):
        if not self.ZK.verify_proof_of_opening(*args):
            raise ValueError(
                f"Failed to verify proof of open for proof {name}", *args
            )

    def prove_sk(
        self,
        ps,
        pe,
        psis,
        peis,
        a,
        p,
    ):
        """
        A proof used in distributed BGV. This method lacks a proof of shortness
        that would be required in a real-world implementation. This has been
        omitted due to time constraints.
        """

        proof_sum = self.ZK.proof_of_sum(ps, pe, self.r0, a, p, 1)
        proof_all_sum = [
            self.ZK.proof_of_sum(psi, pei, self.r0, a, p, 1)
            for psi, pei in zip(psis, peis)
        ]

        proof_open_ps = self.ZK.proof_of_opening(ps)
        proof_open_all_ps = [self.ZK.proof_of_opening(psi) for psi in psis]

        proof_open_pe = self.ZK.proof_of_opening(pe)
        proof_open_all_pe = [self.ZK.proof_of_opening(pei) for pei in peis]

        return (
            proof_sum,
            proof_open_ps,
            proof_open_pe,
            proof_open_all_ps,
            proof_open_all_pe,
            proof_all_sum,
        )

    def verify_sk(
        self,
        b,
        bis,
        a,
        p,
        coms,
        come,
        comsis,
        comeis,
        proof1,
        proof2,
        proof3,
        proofs1,
        proofs2,
        proofs3,
    ):
        comb = self.__commit_r0(b)
        proof, *rest = proof1
        proof = self.__make_proof_open_linear(
            [coms, a, proof[0]], [come, p, proof[1]], [comb, 1, proof[2]]
        )
        self.__verify_sum("Sk", proof, *rest)
        self.__verify_open("Com_s", coms[0][0], proof2)
        self.__verify_open("Com_e", come[0][0], proof3)
        for idx, data in enumerate(bis):
            comb_i = self.__commit_r0(data[1])
            proof, *rest = proofs3[idx]
            proof = self.__make_proof_open_linear(
                [comsis[idx], a, proof[0]],
                [comeis[idx], p, proof[1]],
                [comb_i, 1, proof[2]],
            )
            self.__verify_sum("Com_s, Com_e, Com_b", proof, *rest)
            self.__verify_open("Com_s", comsis[idx][0][0], proofs1[idx])
            self.__verify_open("Com_e", comeis[idx][0][0], proofs2[idx])

    def prove_enc(self, r, m, eprime, ebis, a, b, p):
        com_r, com_m = self.__commit_obj_r_com(r, m)
        com_eprime, com_ebis = self.__commit_obj_r_com(eprime, ebis)
        proof1 = self.ZK.proof_of_sum(com_r.r, com_eprime.r, self.r0, a, p, 1)
        proof2 = self.ZK.proof_of_triple_sum(
            com_r.r, com_ebis.r, com_m.r, self.r0, b, p, 1, 1
        )
        proof3 = self.ZK.proof_of_opening(com_r.r)
        proof4 = self.ZK.proof_of_opening(com_m.r)
        proof5 = self.ZK.proof_of_opening(com_eprime.r)
        proof6 = self.ZK.proof_of_opening(com_ebis.r)
        return (
            proof1,
            proof2,
            proof3,
            proof4,
            proof5,
            proof6,
            self.comm_scheme.commit(com_r),
            self.comm_scheme.commit(com_m),
            self.comm_scheme.commit(com_eprime),
            self.comm_scheme.commit(com_ebis),
        )

    def verify_enc(
        self,
        a,
        b,
        p,
        u,
        v,
        proof1,
        proof2,
        proof3,
        proof4,
        proof5,
        proof6,
        com_r,
        com_m,
        com_eprime,
        com_ebis,
    ):
        com_u = self.__commit_r0(u)
        com_v = self.__commit_r0(v)
        proof, *rest = proof1
        proof = self.__make_proof_open_linear(
            [com_r, a, proof[0]],
            [com_eprime, p, proof[1]],
            [com_u, 1, proof[2]],
        )
        self.__verify_sum("Com_r, com_eprime, com_u", proof, *rest)

        proof, *rest = proof2

        proof = self.__make_proof_open_linear(
            [com_r, b, proof[0]],
            [com_ebis, p, proof[1]],
            [com_m, 1, proof[2]],
            [com_v, 1, proof[3]],
        )
        self.__verify_triple_sum("Com_r, Com_ebis, Com_m, Com_v", proof, *rest)
        self.__verify_open("Com_r", com_r[0][0], proof3)
        self.__verify_open("Com_m", com_m[0][0], proof4)
        self.__verify_open("Com_eprime", com_eprime[0][0], proof5)
        self.__verify_open("Com_ebis", com_ebis[0][0], proof6)
        # If nothing has raised a ValueError until here, the verification is True.
        return True

    def prove_s(self, a_vec, random_vec):
        r0, r1 = self.__commit_obj_r_com(*random_vec)
        proof = self.ZK.proof_of_sum(r0.r, r1.r, self.r0, a_vec[0], a_vec[1], 1)
        return (
            proof,
            self.comm_scheme.commit(r0),
            self.comm_scheme.commit(r1),
        )

    def verify_s(self, a_vec, sum_y, proof, rc0, rc1):
        com_sum = self.__commit_r0(sum_y)
        proof, *rest = proof
        proof = self.__make_proof_open_linear(
            [rc0, a_vec[0], proof[0]],
            [rc1, a_vec[1], proof[1]],
            [com_sum, 1, proof[2]],
        )
        self.__verify_sum("Rc, com_sum", proof, *rest)
        return True

    def prove_r(self, a_vec, random_vec, sum_random):
        r0, r1 = self.__commit_obj_r_com(*random_vec)

        proof1 = self.ZK.proof_of_sum(
            r0.r, r1.r, sum_random, a_vec[0], a_vec[1], 1
        )
        proof2 = self.ZK.proof_of_opening(
            sum_random
        )  # This should be a proof of trapdoor opening
        return (
            proof1,
            proof2,
            self.comm_scheme.commit(r0),
            self.comm_scheme.commit(r1),
        )

    def verify_r(self, proof1, proof2, rc0, rc1, a_vec, c_sum):
        proof, *rest = proof1
        proof = self.__make_proof_open_linear(
            [rc0, a_vec[0], proof[0]],
            [rc1, a_vec[1], proof[1]],
            [c_sum, 1, proof[2]],
        )
        self.__verify_sum("Rc, c_sum", proof, *rest)
        self.__verify_open("c_sum", c_sum[0][0], proof2)
        return True

    def prove_ds(self, p_si, p_ei, u, lagrange, p):
        proof1 = self.ZK.proof_of_opening(p_si)
        proof2 = self.ZK.proof_of_opening(p_ei)
        proof3_fac = lagrange * u
        proof3 = self.ZK.proof_of_sum(p_si, p_ei, self.r0, proof3_fac, p, 1)
        return (proof1, proof2, proof3, proof3_fac)

    def verify_ds(
        self, proof1, proof2, proof3, proof3_fac, p, com_si, com_ei, ds
    ):
        com_ds = self.__commit_r0(ds)
        self.__verify_open("Com_si", com_si[0][0], proof1)
        self.__verify_open("Com_ei", com_ei[0][0], proof2)
        proof, *rest = proof3
        proof = self.__make_proof_open_linear(
            [com_si, proof3_fac, proof[0]],
            [com_ei, p, proof[1]],
            [com_ds, 1, proof[2]],
        )
        self.__verify_sum("Com_si, com_ei, com_ds", proof, *rest)
        return True
