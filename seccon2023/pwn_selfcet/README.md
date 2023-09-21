We have BOF in a struct that contains a function pointer and arguments for the function. The function pointer and the second argument can be fully controlled, and the first 4 bytes of the first argument can be controlled. However, we can only jump to the start of a valid function due to the ENDBR check before the indirect call. 

At the first stage of the exploit, we have to leak the libc address by overwriting the first argument to read@got and partially overwriting the fptr to change err@libc to warn@libc. (1/16 probability) And then, we can call signal(SIGABRT, entrypoint) and trigger the abort signal by overwriting the stack cookie to enable the repetition of the exploit.

Due to the function argument constraints, dprintf(fd, fmt, ...) should be used for the arbitrary read. Since we don't have an address of input data, we have to leak a stack address by calling dprintf with the format string "%s(%s%c%#tx) [%p]" in libc and then leak the stack cookie.

Finally, we can overwrite the return address to one gadget to get a shell.

See the full exploit in [`exploit.py`](exploit.py).