import os
import sys
import time
from GKS23.GKS import GKS
from utils.values import default_values, Q

NUM_TIMES = 5


def __time_between(name: str, func):
    path = os.path.join(sys.path[0], name + "_runtime.txt")
    with open(path, "+w") as f:
        times = []
        for _ in range(NUM_TIMES):
            start_time = time.time()
            func()
            total_time = time.time() - start_time
            times.append(total_time)
            f.write(str(total_time) + "\n")
            print(
                f"Time to {name} took a total of {round(total_time, 6)} seconds."
            )
        average_time = sum(times) / NUM_TIMES
        print(
            f"Average time to run {name} {NUM_TIMES} times was: {average_time} seconds."
        )


def __gks_init():
    gks = GKS(Q, **default_values)
    return gks, gks.KGen()


def measure_GKS_KGen():
    __time_between("GKS_KGen", __gks_init)


def measure_GKS_sign():
    def func():
        m = gks.get_message()
        gks.sign(m, participants[: gks.t])

    gks, participants = __gks_init()
    __time_between("GKS_Sign", func)


def measure_GKS_vrfy():
    def func():
        gks.vrfy(m, next(iter(participants)), next(iter(signature)))

    gks, participants = __gks_init()
    m = gks.get_message()
    signature = gks.sign(m, participants[: gks.t])
    __time_between("GKS_Verify", func)


if __name__ == "__main__":
    measure_GKS_KGen()
