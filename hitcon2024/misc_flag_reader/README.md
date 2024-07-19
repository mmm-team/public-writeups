# Flag Reader - Misc

By: Lyndon

> Update a tar with flag.txt (if you can), and I will read it for you.
>
> [`flag_reader.tar.gz`](https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/flag_reader/flag_reader-d2c3fa42e56f65b5c09b72a55be2e11cf3384d54.tar.gz)
>
> `nc flagreader.chal.hitconctf.com 22222`

- Author: maple3142
- Solves: 24

## Challenge

In `server.py`:

```py
#!/usr/bin/env python3
from base64 import b64decode
from tempfile import TemporaryDirectory
import tarfile, subprocess
from pathlib import Path


def check_tar(tar):
    for member in tar.getmembers():
        if not member.isfile():  # only files are allowed
            return False
        if "flag.txt" in member.name:  # no flag.txt allowed
            return False
    return True


if __name__ == "__main__":

    with TemporaryDirectory() as tmpdir:
        tarbin = b64decode(input("Enter a base64 encoded tar: "))
        uploadTar = Path(tmpdir) / "upload.tar"
        uploadTar.write_bytes(tarbin)

        with tarfile.open(uploadTar, "r:") as tar:
            if not check_tar(tar):
                print("Invalid tar")
                exit(1)

        extractDir = Path(tmpdir) / "extract"
        extractDir.mkdir()
        proc = subprocess.run(
            ["tar", "-xf", uploadTar, "-C", extractDir],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        print(proc.stdout)
        print(proc.stderr)

        print("Extracted files:")
        for f in extractDir.iterdir():
            print(f.name)

        flag = extractDir / "flag.txt"
        if flag.exists():
            print(flag.read_text())
```

## Overview

This is a `tar` exploit challenge. The server accepts a base64 encoded tar file and then performs the
following:

- It first stores the tar file in the filesystem at `/tmp/tmp-randomdirectory/upload.tar`.
- It validates each member inside the tar file using Python's `tarfile` API by asserting that:
  - the member is a file, using `member.isfile()`
  - the member is not called `flag.txt`
- Following the validation check, it executes `tar -xf upload.tar -C extract` in a shell, and throws if the command exits with a non-zero exit code.
- If the tar is deemed valid, it outputs the name of each extracted file within the `extract/` directory.
- Finally, outputs the content of `extract/flag.txt`, if it exists.

The flag itself is stored at `/flag.txt`.

## Solution

At first, it appears that the flag is unreachable from inside the temporary directory. However, it is susceptible to a symlink attack by placing a symlink inside the tar
file that points `flag.txt -> /flag.txt`, which when extracted will be automatically linked to the server's `/flag.txt` regardless of what directory we are currently in.

The main problem is that this would trip *both* validation checks, since it is called `flag.txt` and also not a file (but a symlink). Seemingly, the only way to circumvent
this is either to find a bug in `tar` or in the `tarfile` library.

After scrolling through CPython GitHub issues and filtering for `tar` issues, I came across [GH #120740](https://github.com/python/cpython/issues/120740) which seems to do
exactly what we want. According to the bug description,

> When reading a tar archive that includes a file with a bad header (such as a checksum mismatch), `getmembers` simply stops listing the members at that file, without
> reporting an error, and ignoring the files that come after it (Edit: unless `ignore_zeros=True` is set).

On the other hand, it is cited that "GNU tar 1.34 correctly identifies error and continues processing".

Attempting this exploit, we found that while `tar` will continue processing, it also returns a *nonzero* exit code. This is problematic because `subprocess.run`'s `check`
argument is set to `False`, which means an error will cause the program to exit. The Dockerfile actually uses `busybox tar`, but this behavior is still consistent with
`GNU tar`.

Digging into the CPython source code, we can see that an `InvalidHeaderError` is raised upon an invalid checksum:

```py
if chksum not in calc_chksums(buf):
    raise InvalidHeaderError("bad checksum")
```

We can eventually trace this back to the logic inside the `next()` function (what `getmembers` uses to retrieve the next member):

```py
while True:
    try:
        ...
    except InvalidHeaderError as e:
        if self.ignore_zeros:
            self._dbg(2, "0x%X: %s" % (self.offset, e))
            self.offset += BLOCKSIZE
            continue
        elif self.offset == 0:
            raise ReadError(str(e)) from None
    except EmptyHeaderError:
        ...
    break
```

If an `InvalidHeaderError` is raised while the file offset is greater than zero, `getmembers` will unconditionally stop iterating over the rest of the members.

If we can find a way to trigger another `InvalidHeaderError` that does not trip up `busybox tar`, we can effectively sneak in a `flag.txt` symlink without being detected.
It just so happens that the error is also present inside `nti()`, which is a Python helper that parses the *numbers* inside a tar file:

```py
def nti(s):
    """Convert a number field to a python number.
    """
    # There are two possible encodings for a number field, see
    # itn() below.
    if s[0] in (0o200, 0o377):
        n = 0
        for i in range(len(s) - 1):
            n <<= 8
            n += s[i + 1]
        if s[0] == 0o377:
            n = -(256 ** (len(s) - 1) - n)
    else:
        try:
            s = nts(s, "ascii", "strict")
            n = int(s.strip() or "0", 8)
        except ValueError:
            raise InvalidHeaderError("invalid header")
    return n
```

The logic first checks whether the first byte is `0x80` or `0xff`, in which case it uses some custom integer parsing algorithm. Otherwise (and this is the default way
integers are stored in a tar file), it reads the whole thing as a zero-padded octal string. We can therefore trick `getmembers()` by simply replacing an integer field
with an invalid integer whose first byte is neither `0x80` nor `0xff`.

However, we also need to trick `tar` into *not* raising a nonzero exit code. Looking into the `busybox` [implementation](https://github.com/brgl/busybox/blob/master/archival/libarchive/get_header_tar.c)
of `tar`, we see that it raises an error when the `(str[0] & 0x80) == 0`:

```c
...
if (*end != '\0' && *end != ' ') {
    int8_t first = str[0];
    if (!(first & 0x80))
        bb_error_msg_and_die("corrupted octal value in tar header");
    ...
```

... but there is no additional check beyond that! This means that setting the first byte of the field to `0x81` will fail in Python, but not `busybox`. The parsed integer
will probably be garbage, but that doesn't really matter. We do have to make sure that the tar file's checksum is still valid when replacing a field with the fake data,
but with this we were able to obtain the flag. My exploit script can be found in `solve.py`.
