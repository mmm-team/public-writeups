# Make ROP Great Again

> PWN
>
> author:ShiftCrops
>
> 37 solves

## Vulnerability

This is a very small binary and we are given source so it is easy to see that there is a stack buffer overflow that will allow us to ROP. However the challenge comes from the fact that the binary is so small, so there are few useful gadgets.

## Exploit

The goal is to leak a libc address and jump to a one gadget to pop a shell. But the problem is that no `pop rdi` gadget exists in the binary, which is needed to provide an argument to function calls. One thing we are able to do is call `gets` and `puts`, which happen to leave pointers to `_IO_stdfile_0_lock` and `_IO_stdfile_1_lock` respectively in rdi. I do not understand these structures exactly, but when we call `gets` there appears to be 2 4-byte values followed by a pointer written to `_IO_stdfile_0_lock`. If we can call `puts` on this address we should leak the pointer. However, we need to fill in the first 8 bytes. This is the next problem, `gets` always appends a null byte, so we cannot leak the pointer this way.

Except, each call to `gets` actually decrements the second int, so the subtraction can cause 0 in the LSB to become 0xff. So by writing the first null byte to the LSB of the second int, the decrement will allow a call to `puts` to leak the pointer. One small difficulty to overcome is that `gets` will hang if the pointer exists, so we must actually overwrite it with null bytes during setup. Here is the sequence I used to leak the pointer:

1. Write 0xff to the first 8 bytes of `_IO_stdfile_0_lock` and 0x00 to clear the pointer in the next 8 bytes
2. Write 4 characters to the buffer, when the null byte is appended it will be decremented, causing it to become 0xff
3. Call `puts` to leak the pointer
4. The pointer is mmap-relative, so we can calculate the libc base
5. Return to main to create a second ROP chain

With the leak we can calculate the address of our one shot RCE gadget, jump to it, and get shell.

## Flag

`SECCON{53771n6_rd1_w17h_6375_m4k35_r0p_6r347_4641n}`
