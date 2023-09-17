# jumpout

The control flow is messed up, but we can look at the function fragments and guess how the flag is checked.

We have:
```
sub_1360(f, i):
    return (f ^ 0x4010[i] ^ 0x55 ^ i)
sub_1480:
    checks flag len == 0x1d
    checks sub_1360(flag[i], i) == 0x4030[i]
```
so we have `flag[i] == 0x4010[i] ^ 0x55 ^ i ^ 0x4030[i]`.

Solve script in [solve.py](`solve.py`).
