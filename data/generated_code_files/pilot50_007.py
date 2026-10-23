import numpy as np
import matplotlib.pyplot as plt


def plot_line_graph(x_values, y_values, title="Line Graph"):
    x = np.array(x_values)
    y = np.array(y_values)

    plt.figure(figsize=(8, 5))
    plt.plot(x, y, marker="o", linestyle="-")
    plt.title(title)
    plt.xlabel("X Values")
    plt.ylabel("Y Values")
    plt.grid(True)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    x_data = [1, 2, 3, 4, 5]
    y_data = [2, 4, 6, 8, 10]

    plot_line_graph(x_data, y_data, "Sample Line Graph")