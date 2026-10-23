import ctypes
import ctypes.util

def main():
    libc_name = ctypes.util.find_library('c')
    if not libc_name:
        raise OSError('Cannot find C standard library')
    libc = ctypes.CDLL(libc_name)
    libc.getpid.restype = ctypes.c_int
    pid = libc.getpid()
    print(f'Process ID from C: {pid}')
    libc.printf.argtypes = [ctypes.c_char_p]
    libc.printf(b'Hello from C standard library!\n')

if __name__ == '__main__':
    main()
