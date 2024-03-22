import numpy as np
from BDLOP16.CommitmentScheme import CommitmentScheme
from SecretSharing.SecretShare2 import SecretShare
from BGV122.Participant import Participant
from type.classes import NameData, Sk
from utils.Polynomial import Polynomial


class BGV:
    def __init__(
        self,
        t: int = 2,
        n: int = 4,
        p: int = 2029,
        q: int = 2**32 - 527,
        N: int = 1024,
    ):
        self.t = t
        self.n = n
        self.q = q
        self.N = N
        self.p = p
        self.comm_scheme = CommitmentScheme(q=self.q, N=self.N)
        self.polynomial = self.comm_scheme.polynomial
        self.cypari = self.comm_scheme.cypari
        self.secret_share = SecretShare((self.t, self.n), self.q)
        self.participants: tuple[Participant, ...] = tuple(
            Participant(self.comm_scheme, self.secret_share, self.p)
            for _ in range(n)
        )
        self.names = [i.name for i in self.participants]

    def __recv_value(self, attr):
        try:
            return [i.share_attr(attr) for i in self.participants]
        except Exception as e:
            raise ValueError(
                f"Invalid attribute name in class Participant: {attr}, {e}"
            )

    def __recv_value_shared(self, attr):
        return tuple(i.share_others_attr(attr) for i in self.participants)

    def __share_data(self, attr, data):
        for i in self.participants:
            res = tuple(filter(lambda p: p.name != i.name, data))
            i.recv_from_other(attr, res)

    def __recv_share(self, attr_name: str):
        return self.__share_data(attr_name, self.__recv_value(attr_name))

    def __assert_value_matches_hash(self, attr):
        """
        Takes in the hash of an attr all participants, then all values. Then each
        participant does a check if the hashes they received correspond to the
        value they received when hashed.
        """
        self.__recv_share(attr + "_hash")
        self.__recv_share(attr)
        for i in self.participants:
            if not i.compare_hash(attr).data:
                raise ValueError(
                    f"Aborting. {attr} and {attr}_hash do not match for user {i.name}"
                )

    def __compute_b(self):
        """
        Computes b for all participants, shares a hash of b with the others.
        """
        for i in self.participants:
            i.make_b()
        self.__recv_share("b_hash")

    def __share_b_bar(self):
        for i in self.participants:
            i.make_secrets()
        self.__share_partials("b_bar")

    def __share_partials(self, attr):
        data = self.__recv_value(attr)
        shares = dict()
        for i in data:
            for j, name in zip(i.data, self.names):
                print(name)
                shares[name] = shares.get(name, []) + [NameData(i.name, j)]
        for part in self.participants:
            part.recv_from_other(attr, shares[part.name])

    def __share_commits(self):
        """
        Shares the c which is the result of committing a Commit object between
        all participants. Also shares said object for s_bar between all users.
        Each participant then looks at their received values and checks if
        all of them open successfully.
        """
        self.__share_partials("coms_s_bar")
        self.__share_partials("c_s_bar")
        self.__share_partials("c_e_bar")
        for part in self.participants:
            part.check_open()

    def __broadcast(self):
        """
        Broadcasts user-specific values between all participants.
        """
        self.__recv_share("c_s")
        self.__recv_share("c_e")
        self.__recv_share("b")

    def __recreate(self):
        """
        Asserts that for all users, their b can be reconstructed from b_bars.
        All combinations are tested for by each participant.
        """
        data = self.__recv_value_shared("b_bar")
        recreated = dict()
        for i in data:
            for j in i.data:
                recreated[j.name] = recreated.get(j.name, []) + [
                    NameData(i.name, j.data)
                ]
        for i in self.participants:
            i.reconstruct(recreated[i.name], self.t)

    def __check_equiv(self, attr):
        all_attr = [getattr(i, attr) for i in self.participants]
        if len(set(all_attr)) != 1:
            raise ValueError(f"Users did not get matching values for {attr}")
        return all_attr.pop()

    def __finalize(self):
        keys = dict()
        for idx, part in enumerate(self.participants):
            pk, sk = part.generate_final()
            keys["sk"] = keys.get("sk", []) + [Sk(part.name, idx + 1, sk)]
            keys["pk"] = keys.get("pk", []) + [pk]

        self.a = self.__check_equiv("sum_a")
        self.b = self.__check_equiv("sum_b")
        secret_keys: tuple[Sk, ...] = tuple(keys["sk"])
        print(secret_keys[0].commit == secret_keys[1].commit)
        print(len(set([i.commit for i in secret_keys])))
        return keys["pk"], secret_keys

    def DKGen(self):
        """
        Key generation method, if any of the methods return false they will
        throw an error. If all succeed we return a public key and a secret key
        for each participant.
        """
        self.__assert_value_matches_hash("a")
        self.__compute_b()
        self.__share_b_bar()
        self.__broadcast()
        self.__assert_value_matches_hash("b")
        self.__recreate()
        self.__share_commits()
        return self.__finalize()

    def enc(self, m):
        r = self.polynomial.gaussian_element(1)
        e_prime = self.polynomial.gaussian_element(1)
        e_bis = self.polynomial.gaussian_element(1)
        mprime = self.cypari.liftall(m) * self.cypari.Mod(1, self.q)
        u = self.a * r + self.p * e_prime
        v = self.b * r + self.p * e_bis + mprime
        return u, v

    def t_dec(self, sk: tuple[Sk, ...], u):
        lagrange = self.secret_share.lagrange([i.x for i in sk])
        M = [coeff * com.commit.m * u for coeff, com in zip(lagrange, sk)]
        E = [self.polynomial.uniform_element(2) for _ in sk]
        d = [m + self.p * e for m, e in zip(M, E)]
        return d

    def comb(self, v, d):
        sum_ds = sum(d)
        ptx = self.cypari.liftall(
            v
            - sum_ds
            + self.cypari.Pol(
                self.cypari.round(np.ones(1024) * ((self.q - 1) / 2))
            )
        ) * self.cypari.Mod(1, self.p)
        ptx -= self.cypari.Pol(self.cypari.round(np.ones(1024) * (1958)))
        return ptx


if __name__ == "__main__":
    bgv = BGV()
    poly = Polynomial(bgv.N, q=bgv.p)
    public_keys, secret_keys = bgv.DKGen()
    results = dict()
    m = poly.uniform_element()
    u, v = bgv.enc(m)
    d = bgv.t_dec(secret_keys[:2], u)
    decrypted = bgv.comb(v, d)
    res = decrypted == m
    results[res] = results.get(res, 0) + 1
    print(results)
