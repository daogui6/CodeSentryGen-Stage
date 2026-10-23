import os
from colored import fg, attr

def print_colored_text(text, color):
    print(fg(color) + text + attr('reset'))

if __name__ == "__main__":
    print_colored_text("Hello, colored world!", "green")
