# Full Chain - Wall Sina

## Overview and Bug

We are given a simple userland binary that reads 64 bytes in a global buffer
(in .bss), calls printf with the first argument as the global buffer - a format
string bug, and returns. Following is the source code for the same:

```c
#include <unistd.h>
#include <stdio.h>

int main();

char buff[0x48];
void *const gift = main;

int main() {
    read(STDIN_FILENO, buff, 0x40);
    printf(buff);
}
```

Note that we also have a gift from the author to help during exploitation - a
function pointer to main in the const region.

## Exploit

Given that the input buffer was not on stack and the binary has PIE enabled, we
basically are looking for a way to call main more than once.

1. First `printf` (as part of normal execution): We notice the stack has a
   `link_map` structure and this is where the gift helps. Modify the
   `link_map->l_addr` (offset 0 and thus it works), to adjust it such that the
   `DT_FINI_ARRAY + modified_image_base` points to the location where `main`
   address is saved. This results in being able to call `printf` again. We
   also make sure to leak all possible values - libc, stack, image, etc.

2. Second `printf` (`DT_FINI_ARRAY`): During the second `printf`, we try to do
   two things:
   - Call `read+printf` again: Modify the image base such that `DT_FINI +
     modified_image_base == main`. This should give the ability to call `main`
     again.
   - Gain write at specific location on stack: Find a stack location `A` whose
     memory content points to another stack address `B` pointing to somewhere
     on stack. Use `A` to overwrite `B` such that it points to the stack
     address where the return value of `printf` will be saved during the
     `DT_FINI` call to `main`.  Starting the third `printf`, we can then use
     `B` to overwrite `printf` return address to start of `read` setup
     instructions in `main` and call `read+printf` in a loop.

3. Third `printf` usage (`DT_FINI`): Similar to second `printf`, we try to do
   similar two things:
   - Try to gain ability to use format string bug again - use `B` to overwrite
     `printf`'s return value
   - Gain ability to write arbitrarily on stack: we can't use `B` because we
     need to have it reserved to loop, but we do find another such stack
     location `C` pointing to `D` which points to somewhere on stack. In our
     exploit we use `D` to write a rop-chain starting from `main`'s return
     address back to `_dl_fini` (which originally called `DT_FINI`).

4. Now we basically run `read+printf` in a loop where we (in no specific order):
   - Use `D` to write rop bytes (2 at a time)
   - Use `C` to increment `D` by 2
   - Use `B` to overwrite `printf` return address to loop except for last write
     when we want to trigger rop chain by returning from `main`.

   NOTE: order doesn't matter because we are using positional arguments

### ROP chain and shell

The environment in which we are running the binary is `chroot`ed and the flag
file is outside the `chroot` root, requiring us to bypass the jail. This is
possible since the setup grants `CAP_SYS_CHROOT` access to `sina` binary
(target binary), allowing `chroot` syscall. This results in the following
rop-chain:

```
chdir("..")
chroot("user")
chdir("..")    // repeat 9 times
chroot("..")
dup2(10, 0)
dup2(11, 1)
dup2(12, 2)
system("/bin/sh")
```

We do `dup2` because our runner binary sets fds `0` and `1` of `sina` to a pipe
to communicate with it. Thus we initially dup fds 0/1/2 to 10/11/12 in runner
and later for shell we reset it back to original input/output fds.

See [exploit.c](exploit.c) for detailed exploit written in `C`.
