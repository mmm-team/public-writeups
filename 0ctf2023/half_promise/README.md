## Half Promise - V8 Pwn Problem - Writeup by Robert Xiao (@nneonneo)

Half Promise was a pwn challenge solved by 8 teams, worth 611 points.

Description:

> Try the half RCE challenge!
> 
> nc chall.ctf.0ops.sjtu.cn 36000

This is a challenge to exploit the [V8](https://v8.dev/) JavaScript engine which powers Chrome. We're provided with a copy of the command-line V8 implementation, d8, that was built with the following configuration:

```
is_debug=false
dcheck_always_on=false
v8_static_library=true
target_cpu="x64"
v8_enable_sandbox=true
v8_enable_object_print=true
v8_expose_memory_corruption_api=true
```

as well as a (standard) patch to disable the default shell global template to prevent trivial solutions.

The crucial configuration item is `v8_expose_memory_corruption_api=true`. This enables the [Memory Corruption API](https://chromium.googlesource.com/v8/v8/+/4a12cb1022ba335ce087dcfe31b261355524b3bf), which gives us effectively read/write access to any part of the V8 heap. This API is meant for testing the V8 sandbox.

> In fact, a very similar problem was present in Google CTF 2023, called V8Box, which I also solved. I was able to take my exploit script for that challenge, tweak some of the constants, and make it work for this challenge.

The general idea behind the exploit is to overwrite the bytecode for a JavaScript function. For speed, the bytecode handlers (`Builtins_*Handler`) do not perform any bounds checking. Thus, by specifying out-of-bounds indices for instructions like `ldar` and `star`, we can read and write on the stack.

Due to the sandbox and pointer compression, most of the pointers on the heap are 32-bit offsets into the 4GB V8 heap region. However, there are a few 64-bit pointers to the native heap lying around, most notably in `MemoryChunk` objects, which we can use to break the ASLR base of the binary.

The exploit script can be found in [`exploit.js`](exploit.js). It performs the following:

1. Define a JS function whose bytecode will be overwritten
2. Use the Memory Corruption API to obtain a writable reference to the function's bytecode
3. Overwrite the bytecode to execute `ldar +1; return`, which will retrieve and return the stored RIP on the stack. This RIP points into the d8 binary, and will be interpreted as an [Smi](https://v8.dev/blog/elements-kinds) when returned to JavaScript, thus allowing us to leak the low 32 bits of an executable pointer.
4. Obtain the high 32 bits of the executable pointer by leaking a native heap address from a MemoryChunk object at a fixed offset in the heap (the MemoryChunk is always at v8 heap base + 0x40000)
5. Construct a ROP chain in memory using gadgets from the d8 binary
6. Overwrite the bytecode again to execute `ldaconstant [0]; star +17; return`, which writes the address of the ROP chain to the saved RBP of a parent stack frame.
7. Upon finishing the JS script, the ROP chain will be triggered, giving us a shell.
