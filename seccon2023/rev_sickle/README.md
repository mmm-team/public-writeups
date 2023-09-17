# Sickle

We can remove all but the last `'.'` in `payload`, then run [fickling](https://github.com/trailofbits/fickling)
on it to get the gist of what it's doing. (This ignores all the control flow though, since we removed the `.`s and ignore all the `f.seek`s.)

We get the following decompilation:
```
_var0 = input('FLAG> ')
_var1 = getattr(_var0, 'encode')
_var2 = _var1()
_var3 = getattr(dict, 'get')
_var4 = globals()
_var5 = _var3(_var4, 'f')
_var6 = getattr(_var5, 'seek')
_var7 = getattr(int, '__add__')
_var8 = getattr(int, '__mul__')
_var9 = getattr(int, '__eq__')
_var10 = len(_var2)
_var11 = _var9(_var10, 64)
_var12 = _var7(_var11, 261)
_var13 = _var6(_var12)
_var14 = getattr(_var2, '__getitem__')
_var15 = _var14(0)
_var16 = getattr(_var15, '__le__')
_var17 = _var16(127)
_var18 = _var7(_var17, 330)
_var19 = _var6(_var18)
_var20 = _var7(0, 1)
_var21 = _var9(_var20, 64)
_var22 = _var8(_var21, 85)
_var23 = _var7(_var22, 290)
_var24 = _var6(_var23)
_var25 = getattr([], 'append')
_var26 = getattr([], '__getitem__')
_var27 = getattr(int, 'from_bytes')
_var28 = _var8(0, 8)
_var29 = _var7(0, 1)
_var30 = _var8(_var29, 8)
_var31 = slice(_var28, _var30)
_var32 = _var14(_var31)
_var33 = _var27(_var32, 'little')
_var34 = _var25(_var33)
_var35 = _var7(0, 1)
_var36 = _var9(_var35, 8)
_var37 = _var8(_var36, 119)
_var38 = _var7(_var37, 457)
_var39 = _var6(_var38)
_var40 = getattr([], 'append')
_var41 = getattr([], '__getitem__')
_var42 = getattr(int, '__xor__')
_var43 = _var26(0)
_var44 = _var42(_var43, 1244422970072434993)
_var45 = pow(_var44, 65537, 18446744073709551557)
_var46 = _var40(_var45)
_var47 = _var41(0)
_var48 = _var7(0, 1)
_var49 = _var9(_var48, 8)
_var50 = _var8(_var49, 131)
_var51 = _var7(_var50, 679)
_var52 = _var6(_var51)
_var53 = getattr([], '__eq__')
_var54 = _var53([8215359690687096682, 1862662588367509514, 8350772864914849965, 11616510986494699232, 3711648467207374797, 9722127090168848805, 16780197523811627561, 18138828537077112905])
result0 = _var54
```

From here, we get something like this:
```
l = []
for i in flag_chunks:
    x = pow(i ^ 1244422970072434993, 65537, 18446744073709551557)
    l.append(x)

# check that l == [8215359690687096682, ..., 18138828537077112905]
```

We can invert `pow(_var44, 65537, 18446744073709551557)` by getting the decryption exponent via `pow(65537, -1, phi(18446744073709551557))`.
We then guessed a bunch of things, like "the first chunk of the flag decrypted correctly, but the rest didn't, so maybe it's doing CBC and that `1244422970072434993` is really the IV".

The corrected version of the encryption is:
```
l = []
prev = 1244422970072434993
for i in flag_chunks:
    x = pow(i ^ prev, 65537, 18446744073709551557)
    l.append(x)

# check that l == [8215359690687096682, ..., 18138828537077112905]
```

Solve script in [solve.py](`solve.py`).
