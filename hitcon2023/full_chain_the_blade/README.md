# The Blade - Reversing

```
Full Chain - The Blade [234pts]

A Rust tool for executing shellcode in a seccomp environment. Your goal is to pass the hidden flag checker concealed in the binary.

https://storage.googleapis.com/hitconctf2023/chal-the-blade/blade-4c2ff1b60902623f702f0245a6a9ea0e71eeb385

(Hey, this is my first Rust project. Feel free to give me any advice and criticism 😃)

Author: wxrdnx
40 Teams solved.
```

## Initial Observations

The binary is a C2 server which has "help" menus that show the various functions available. However, there is no hint to where the flag may be. Stopping in GDB at the prompt and running a backtrace shows that we are in the function `seccomp_shell::cli::prompt`. Looking in Ghidra, most of the important code is in the seccomp_shell namespace.

## Hidden Functions

First, I stepped through the prompt function to see how my input was handled. Although the help menu showed three options, there was a fourth string comparison for "shell".

Second, while looking at the seccomp_shell functions I noticed one named "verify", which was not in the list of help menu options. Doing a cross reference showed that this function is called after a string comparison with "flag."

## Reversing Verification

The verify function takes parameters for a string as well as its length, which must be 64. The first half of this function runs a loop 0x100 times that does multiple substitutions on the string and then performs some mathematical operations character by character. I (aka Copilot) re-wrote this in Python so I could do some testing and run it backwards. The second half of the function had a series of bytes (also 64 in length), followed by what looked like networking functionality. When the verify function was called with a 64 byte string, the process would crash. Some quick reversing showed that it probably had to do with not having a socket to read/write.

At this point I tried to create input that would match the mystery bytes in the verify function, but the required input it wasn't valid ascii. Combined with the crash, I figured I would need to start the C2 server and connect to it via nc. Doing this dropped me into a shell, and I ran the verify command to see what would happen. This sent a byte stream to the client, and every character that I sent back to the server would generate a very similar byte stream. Since this is supposed to be an implant, I assumed the bytestring was shellcode.

The shellcode contained the bytes from the verify function, as well as the output from my modified verify string. It would open the files /etc/passwd, /bin/sh, and /dev/zero and use data from them to modify the verify string even more before matching it against the hard-coded bytes from the function. With this new understanding, I slightly modified my Python script to undo the work of the shellcode, and get the flag.

## Flag

hitcon{<https://soundcloud.com/monstercat/noisestorm-crab-rave>}
