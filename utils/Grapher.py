import matplotlib.pyplot as plt


start = 3
stop = 4 + 1  # Change this to maximum stop value
x = range(start, stop)


def x_label(label_type: str):
    plt.xlabel(f"Total participants ({label_type})")


def y_label(label_type: str):
    plt.ylabel(label_type)


def plot_figs(vals):
    CONSTS = {
        "time": {"idx": 1, "color": "green", "label": "Time (seconds)"},
        "muls": {
            "idx": 2,
            "color": "red",
            "label": "Number of multiplications",
        },
        "adds": {"idx": 3, "color": "blue", "label": "Number of additions"},
    }
    for key in vals:
        idx = CONSTS[key]["idx"]
        color = CONSTS[key]["color"]
        label = CONSTS[key]["label"]
        y = vals[key]["y"]
        plt.figure(idx)
        plt.xticks(x)
        plt.ylabel(label)
        plt.plot(x, y, color)

    plt.show()


def for_n():
    vals = {
        "time": {"y": [17.5, 31]},
        "muls": {"y": [3008, 4895]},
        "adds": {"y": [820, 1355]},
    }
    x_label("n")
    plot_figs(vals)


def for_t():
    vals = {
        "time": {"y": [17.5, 31]},
        "muls": {"y": [3008, 4895]},
        "adds": {"y": [820, 1355]},
    }
    x_label("t")
    plot_figs(vals)


if __name__ == "__main__":
    for_n()
