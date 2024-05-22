import matplotlib.pyplot as plt


def plot_figs(x, vals, x_label):

    CONSTS = {
        "time": {
            "idx": 1,
            "label": "Time (seconds)",
        },
        "multiplications": {
            "idx": 2,
            "label": "Number of multiplications",
        },
        "additions": {"idx": 3, "label": "Number of additions"},
    }
    for key in vals:
        idx = CONSTS[key]["idx"]
        y_label = CONSTS[key]["label"]
        y_KGen = vals[key]["y_KGen"]
        kgen_color = "forestgreen"
        sign_color = "midnightblue"
        y_Sign = vals[key]["y_Sign"]

        plt.figure(idx)
        plt.xticks([2, 3, 4, 5, 6, 7, 8])
        plt.xlabel(f"Participants ({x_label})")
        plt.ylabel(y_label)

        plt.ylim([0, max(y_KGen) * 1.1])
        plt.plot(
            x,
            y_KGen,
            "o--",
            color=kgen_color,
            linewidth=1,
            markersize=5,
            label="KGen",
        )
        if key is "time":

            plt.plot(
                x,
                vals[key]["y_by_part"],
                "o--",
                color="lightseagreen",
                linewidth=1,
                markersize=5,
                label=f"KGen {key} per participant",
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

        plt.legend(loc="upper left")

    plt.show()


def by_part(start, lst: list):
    return [element / (start + i) for i, element in enumerate(lst)]


def for_n():

    start = 4
    stop = 9 + 1
    x = range(start, stop)
    vals = {
        "time": {
            "y_KGen": [
                8.326440333,
                19.27207655,
                40.6679343,
                81.8795173,
                156.3194641,
                300.508963,
            ],
            "y_Sign": [
                2.508029233,
                2.5855829,
                2.571046367,
                2.5593325,
                2.5154323,
                2.593818,
            ],
        },
        "multiplications": {
            "y_KGen": [3008, 4895, 7416, 10661, 14720, 19683],
            "y_Sign": [1182, 1182, 1182, 1182, 1182, 1182],
        },
        "additions": {
            "y_KGen": [820, 1355, 2070, 2989, 4136, 5535],
            "y_Sign": [355, 355, 355, 355, 355, 355],
        },
    }
    for key in vals:
        vals[key]["y_by_part"] = by_part(start, vals[key]["y_KGen"])
    plot_figs(x, vals, "n")


def for_t():
    start = 2
    stop = 7 + 1
    x = range(start, stop)
    vals = {
        "time": {
            "y_KGen": [
                36.666557,
                81.8795173,
                133.650926,
                132.9646166,
                74.9615868,
                35,
            ],
            "y_Sign": [
                1.368143,
                2.5593325,
                4.0479122,
                6.0208873,
                8.072783,
                10.95,
            ],
        },
        "multiplications": {
            "y_KGen": [10661, 10661, 10661, 10661, 10661, 10661],
            "y_Sign": [647, 1182, 1861, 2684, 3651, 4762],
        },
        "additions": {
            "y_KGen": [2989, 2989, 2989, 2989, 2989, 2989],
            "y_Sign": [182, 355, 584, 869, 1210, 1607],
        },
    }

    vals["time"]["y_by_part"] = by_part(start, vals["time"]["y_KGen"])
    plot_figs(x, vals, "t")


if __name__ == "__main__":
    for_t()
