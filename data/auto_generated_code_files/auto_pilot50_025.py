import numpy as np

# Array creation
arr1 = np.array([1, 2, 3, 4, 5, 6])
arr2 = np.array([10, 20, 30, 40, 50, 60])

# Indexing
first_element = arr1[0]

# Slicing
sliced_arr = arr1[1:4]

# Reshaping
reshaped_arr = arr1.reshape(2, 3)

# Element-wise arithmetic
added_arr = arr1 + arr2
multiplied_arr = arr1 * 2

print("First element:", first_element)
print("Sliced array:", sliced_arr)
print("Reshaped array:\n", reshaped_arr)
print("Added array:", added_arr)
print("Multiplied array:", multiplied_arr)
