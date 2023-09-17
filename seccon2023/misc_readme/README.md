## readme 2023 - Misc Problem - Writeup by Robert Xiao (@nneonneo)

readme 2023 was a misc challenge solved by 93 teams, worth 104 points.

Description:

> Can you read the flag?
> 
> `nc readme-2023.seccon.games 2023`
> 
> readme2023.tar.gz 94b27f30a219fe4476c3f4c1df0e1fca5dbb2c0b

We're given the following Python script running on a server:

```
import mmap
import os
import signal

signal.alarm(60)

try:
    f = open("./flag.txt", "r")
    mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
except FileNotFoundError:
    print("[-] Flag does not exist")
    exit(1)

while True:
    path = input("path: ")

    if 'flag.txt' in path:
        print("[-] Path not allowed")
        exit(1)
    elif 'fd' in path:
        print("[-] No more fd trick ;)")
        exit(1)

    with open(os.path.realpath(path), "rb") as f:
        print(f.read(0x100))
```

This script maps a flag into memory and then lets the user read the first 256 bytes of any file, except files with `fd` or `flag.txt` in the path.

## Solution

`/proc/self/map_files` contains one file for each memory mapping in the process, named with the start and end of the memory region (e.g. `7ff2acb89000-7ff2acb8a000`), so our flag will be in one of these files. However, due to ASLR, we will need to leak the address of the region first.

Because of the 256-byte limit, `/proc/self/maps` only yields the addresses of the Python binary's memory regions, not any of the mmap regions. We wrote a short script to go through all of the files on a local instance, and found that the file `/proc/self/syscall` contains a pointer that is near the flag's memory address. In fact, the final entry of `/proc/self/syscall` is the address of the program counter during the `read` syscall that is reading the file, which points to the `read` function in libc. Since libraries are allocated with `mmap` too, they are in the same memory region as the mmap'd flag, so the flag region will have an address near the leaked `syscall` address.

Thus, the exploit is to dump `/proc/self/syscall`, add the fixed offset 0xe9f83 to the last entry and then read the flag's `map_file`:

```
$ nc readme-2023.seccon.games 2023
path: /proc/self/syscall
b'0 0x7 0x562200d0a6b0 0x400 0x2 0x0 0x0 0x7fff685cdda8 0x7fe510a5d07d\n'
path: /proc/self/map_files/7fe510b47000-7fe510b48000
b'SECCON{y3t_4n0th3r_pr0cf5_tr1ck:)}\n'
```
