# 3dsboy

When opening up the rom in citra, we notice that we can collect up to 5 flowers.

Looking at the rom in IDA using [this loader](https://github.com/0xEBFE/3DSX-IDA-PRO-Loader), we
notice that the function at `0x10F4B8` (loader base is `0x108000`) looks like a check function:
we're taking 2 ints, then evaluating 3 linear functions on them and checking the output.

We can guess that these 2 ints are the `x` and `y` position when collecting a flower.

We then run citra with the gdb stub enabled, and in `arm-none-eabi-gdb`, we run:

```
# we use gef...
gef-remote localhost 24689
break *0x1076fc

# now collect 5 flowers

# repeat this 5 times for each value of x and y
set *($r8 + ($r5 << 3)) = [x]
set *($r10 + ($r5 << 3)) = [y]
c
```

and we get the flag on the lower screen.

Equation extraction in `extract.py`.

Equation solver in `solve.sage`.
