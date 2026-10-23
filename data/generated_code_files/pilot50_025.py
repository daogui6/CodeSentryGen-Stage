import numpy as np


def demonstrate_array_operations() -> None:
    array = np.arange(1, 13)

    print("Original array:")
    print(array)

    print("\nIndexing:")
    print("First element:", array[0])
    print("Last element:", array[-1])

    print("\nSlicing:")
    print(array[2:8])

    matrix = array.reshape(3, 4)
    print("\nReshaped matrix:")
    print(matrix)

    print("\nElement-wise arithmetic:")
    print("Matrix + 10:")
    print(matrix + 10)

    print("\nMatrix squared:")
    print(matrix ** 2)

    print("\nColumn means:")
    print(matrix.mean(axis=0))

    print("\nRow sums:")
    print(matrix.sum(axis=1))


if __name__ == "__main__":
    demonstrate_array_operations()
