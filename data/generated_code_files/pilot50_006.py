def first_ten_characters(text):
    return text[:10]


if __name__ == "__main__":
    user_input = input("Enter a string: ")
    result = first_ten_characters(user_input)
    print(result)