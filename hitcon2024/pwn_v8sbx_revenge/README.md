# V8 SBX Revenge

```
nc v8sbx.chal.hitconctf.com 1338

https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/v8sbx_revenge/v8sbx_revenge-772b4668c5867082df541cfcecaa0f81caaf36e8.tar.gz

Author: ljp_tw
13 Teams solved.
```


## Analysis

We're given a `v8.patch` that adds:
- `Sandbox.modifyTrustedPointerTable(handle, pointer, tag)` that writes any desired value into the trusted pointer table that can be used only once*
  - *The function does a check `times` -> params `ToInteger()` -> increment `times` so the check is broken and the primitive can be triggered arbitrarily many times:
    ```js
    console.log(Sandbox.modifyTrustedPointerTable(
        {
            [Symbol.toPrimitive]() {
                console.log(Sandbox.modifyTrustedPointerTable(0x400000, 1, 2));
                return 0x402000;
            }
        }, 2, 3
    ));
    ```
- `Sandbox.H32BinaryAddress()` that returns the upper dword of the binary address (specifically, `Sandbox.H32BinaryAddress` itself)

But that being said, we don't even need to look at these patches as all memory corruption APIs are still available. There's a lot of v8 sandbox 0/1-days so we can find and use anything that suits our purposes.


## Exploit

Base commit is `97d99259d002b24271ca4c3cf2469349e7a5406e` which is several weeks old. There are multiple sandbox-related commits, some even with concrete PoCs obtaining arbitrary writes.

One example is [`2f16c5f`](https://chromium.googlesource.com/v8/v8.git/+/2f16c5f7b56c40c1faeca4c14e897ac453d6b5ba) - this is caused by corrupting `WasmTableObject.length` to a negative size using in-sandbox primitives, then attempting to set a large index corresponding to a negative value when considered as a signed integer. This passes all initial bounds check, and even passes a `SBXCHECK_LT()` comparison against `WasmDispatchTable::length()` in the trusted region explicitly designed to prevent this as the comparison is signed.

This allows an out-of-bounds write in the trusted space with a negative index which we can abuse to overwrite other function entries in the `WasmDispatchTable`, leading to function signature confusion and thus arbitrary address read/write (via `i64 -> ref` parameter type confusion) as well as a stable infoleak of the JIT address from the stack (via return count confusion).

The exploit is now trivial, use the AAR/W and infoleak to obtain RCE. As we do not know whether the challenge server has Intel MPK enabled (which would block naive attempts to overwrite JIT code directly), we simply try overwriting target JIT code to shellcode - the server did not have it enabled, and we pop shell.


## Solution

Solver script is here: [exp_send.js](./exp_send.js). WASM code is based on [exp.js](./exp.js).
