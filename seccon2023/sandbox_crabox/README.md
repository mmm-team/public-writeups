# crabox - Sandbox Problem - Writeup by f0xtr0t

> (132 pt)
> author:Arkwarmup
>
> 🦀 Compile-Time Sandbox Escape 🦀
>
> nc crabox.seccon.games 1337
>
> [crabox.tar.gz](./crabox.tar.gz) 713d208b472f6a654bf6685f0d38b5aacca93942

## Overview

We are given a [small Python file](./app.py) (along with Docker setup to run
it), that takes up to 512 bytes of input, and places it into the following
template (along with placing in the flag):

``` rust
fn main() {
    {{YOUR_PROGRAM}}

    /* Steal me: {{FLAG}} */
}
```

It then compiles this file (created with a random file name in `/tmp/`) with
`rustc` (sending both stdout and stderr to `/dev/null`), and tells us (with a
smiley) whether the return code for `rustc` was 0 or not.

Thus overall, the challenge is to leak the flag that is in the comment, while
only having access to a "did it compile or not" bit of information.

## Attack

Rust has support for some compile-time code execution. In particular, some code
and macros can be used in `const` context, and we can use this to get the flag,
one bit at a time.

In particular, we use the `file!()` macro to get the current file's path, then
pass it into `include_bytes!()` to get the current file as a byte-array. We can
then use an `assert!()` macro (inside a `const` unit) to check the value of the
byte at some index in the array. If the assert succeeds, compilation succeeds;
otherwise compilation fails.

We can use a binary search for possible values in order to narrow down the
specific bytes quite quickly, thus we use a `<=` check in the `assert!()`.

This leads to the following template:

``` rust
const F: &[u8] = include_bytes!(file!());
const _T: () = assert!(F[F.len() - POSITION] <= GUESSNUM);
```

Note that `F` contains the contents of the entire source file, read in as bytes,
and that the `const _T: () = ...` forces the `assert!` to run in a
const-context, forcing compile-time evaluation.

By looking at characters from the end of the file, we don't need to actually
account for how long our payload is, and can just keep reading backwards until
we read the whole flag.

## Solve Script

See [solve.py](./solve.py). It is a fairly straightforward implementation of the
approach mentioned above.

While we could _technically_ parallelize across all characters, this is not
necessary since the whole script runs quite fast.

## Flag 

```
SECCON{ctfe_i5_p0w3rful}
```

The reference here of course is to Rust's compile-time function evaluation,
which indeed is powerful.
