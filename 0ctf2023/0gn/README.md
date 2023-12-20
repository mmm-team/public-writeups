## 0gn - Reversing Problem - Writeup by Robert Xiao (@nneonneo)

0gn was a reversing problem solved by 10 teams, worth 550 points.

Description:

> Just `bash run.sh $FLAG`.
> 
> attachment

The attachment contains a `node` binary, a `flagchecker.js` script, and a `run.sh` Bash script that runs `./node ./flagchecker.js` after checking the integrity of both files.

`flagchecker.js` is obfuscated. [Synchrony](https://deobfuscate.relative.im/) does a good job cleaning it up; fixing up a few `String.fromCharCode` obfuscations results in [`flagchecker.deobf.js`](flagchecker.deobf.js).

The script is quite simple: the class `MMM` implements the MD5 hash algorithm, and the class `a` contains most of the flag checking logic. `a.resultchecker` checks if the MD5 hash of the input is equal to `cd9e459ea708a948d5c2f5a6ca8838cf` (which is the hash of `00000000000000000000000000000000`). `a.flagchecker` checks the flag format (must be 38 chars of the format `flag{...}`), then passes the flag contents as a Buffer to `resultchecker`.

Running `node flag{00000000000000000000000000000000}` using a normal build of Node produces `Right!`. However, running with the provided `node` binary produces `Wrong!`. Thus, the provided `node` binary must be backdoored such that it overrides the normal logic of the flag checker script.

After some experimentation, it seems that the backdoored `node` binary is rewriting any method call of the form `x.y(z)` (equivalently `x["y"](z)`), where `y` contains the string "resultchecker". The rewritten code first calls the original function `x.y`, then adds a bunch of extra logic which is presumably the real flag check. The challenge authors have disabled `--print-bytecode`, so we cannot trivially view the rewritten code, and a cursory look through the 70+MB node binary doesn't immediately reveal the backdoor injection code - which is presumably sitting somewhere in the V8 Ignition bytecode compiler. Note that the backdoored Node binary crashes when attempting to JIT (TurboFan) any function that contains a call to `x.resultchecker`, indicating that the backdoor probably works by injecting bytecode.

To dump the raw bytecode, we can use `%DebugPrint` (`--allow-natives-syntax`) with `%SystemBreak` under GDB, for example, using the following script:

```js
z = {resultchecker: (x) => 0, d: 42};
function foo() {
  return z.resultchecker(0);
}
foo();
%DebugPrint(foo);
%SystemBreak();
```

At the breakpoint, we can dump the memory referenced by the `bytecode` property of the function in the DebugPrint output. This yields a large bytecode array (1063 bytes: [`bytecode.bin`](bytecode.bin)), where the bytecode for such a function would usually just be a few bytes long.

Comparing bytecode for various functions between the backdoored Node and normal Node, we observe that most of the opcodes seem to be the same, but a handful of them have been renumbered. To compensate, I wrote a simple disassembler in Python ([`disas.py`](disas.py)) that uses a modified version of an opcode table from [v8-disassembler/v8_opcodes](https://github.com/v8-disassembler/v8_opcodes). This dumps out readable disassembly in [`disas.txt`](disas.txt).

From the disassembly, we can tell that the injected bytecode mutates the entries in the input using add, sub and xor with various constants, then passes the input Buffer to runtime function 0x1db along with the constant 0x6a8838cf.

This runtime function turns out to be `Runtime_TypedArrayVerify`, which is not a real V8 function. This function implements some kind of encryption algorithm, which has a design similar to TEA/XTEA in CBC mode. It encrypts the input buffer and then compares it with a fixed constant. The 32-bit constant input is used to derive a 64-bit IV and 64-bit key for the encryption algorithm. [`solve.py`](solve.py) implements the decryption algorithm and undoes the bytecode's mutations; when run, we get the flag: `flag{97170f6727bc6757e69eb04c045478be}`.
