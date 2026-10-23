import ctypes
import ctypes.util
import sys


class CLibrary:
    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c")

        if libc_name is None:
            raise RuntimeError("Unable to find the C standard library")

        self.libc = ctypes.CDLL(libc_name)
        self._configure_functions()

    def _configure_functions(self) -> None:
        self.libc.strlen.argtypes = [ctypes.c_char_p]
        self.libc.strlen.restype = ctypes.c_size_t

        self.libc.abs.argtypes = [ctypes.c_int]
        self.libc.abs.restype = ctypes.c_int

        self.libc.puts.argtypes = [ctypes.c_char_p]
        self.libc.puts.restype = ctypes.c_int

    def strlen(self, value: str) -> int:
        return int(self.libc.strlen(value.encode("utf-8")))

    def abs(self, value: int) -> int:
        return int(self.libc.abs(value))

    def puts(self, value: str) -> None:
        self.libc.puts(value.encode("utf-8"))


def main() -> None:
    c_library = CLibrary()

    print("Python version:", sys.version)
    print("strlen('hello'):", c_library.strlen("hello"))
    print("abs(-42):", c_library.abs(-42))

    c_library.puts("Message printed through libc.puts")


if __name__ == "__main__":
    main()
