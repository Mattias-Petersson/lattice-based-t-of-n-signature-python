import matplotlib.pyplot as plt


def plot_figs(x, vals, x_label):
    CONSTS = {
        "time": {
            "idx": 1,
            "label": "Time (seconds)",
        },
        "muls": {
            "idx": 2,
            "label": "Number of multiplications",
        },
        "adds": {"idx": 3, "label": "Number of additions"},
    }
    for key in vals:
        idx = CONSTS[key]["idx"]
        y_label = CONSTS[key]["label"]
        y_KGen = vals[key]["y_KGen"]
        kgen_color = "forestgreen"
        sign_color = "midnightblue"
        y_Sign = vals[key]["y_Sign"]
        plt.figure(idx)
        plt.xticks(x)
        plt.xlabel(f"Total participants ({x_label})")
        plt.ylabel(y_label)
        plt.ylim([0, y_KGen[-1] * 1.1])
        plt.plot(
            x,
            y_KGen,
            "o--",
            color=kgen_color,
            linewidth=1,
            markersize=5,
            label="KGen",
        )
        plt.plot(
            x,
            y_Sign,
            "o--",
            color=sign_color,
            linewidth=1,
            markersize=5,
            label="Sign",
        )

        plt.legend()

    plt.show()


def for_n():
    start = 4
    stop = 8 + 1
    x = range(start, stop)
    vals = {
        "time": {
            "y_KGen": [
                8.326440333,
                19.27207655,
                40.6679343,
                81.8795173,
                156.3194641,
            ],
            "y_Sign": [
                2.508029233,
                2.5855829,
                2.571046367,
                2.5593325,
                2.5154323,
            ],
        },
        "muls": {
            "y_KGen": [3008, 4895, 7416, 10661, 14720],
            "y_Sign": [1182, 1182, 1182, 1182, 1182],
        },
        "adds": {
            "y_KGen": [820, 1355, 2070, 2989, 4136],
            "y_Sign": [355, 355, 355, 355, 355],
        },
    }
    plot_figs(x, vals, "n")


def for_t():
    vals = {
        "time": {"y": [17.5, 31]},
        "muls": {"y": [3008, 4895]},
        "adds": {"y": [820, 1355]},
    }
    plot_figs(vals, "t")


if __name__ == "__main__":
    for_n()
