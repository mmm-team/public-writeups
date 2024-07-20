# Revisual - Rev

```
Try to break into this beautiful starry vault.

http://revisual.chal.hitconctf.com/

Author: bronson113
30 Teams solved.
```

We're given [`index.html`](./index.html) and [`script.min.js`](./script.min.js).

## Reversing

The objective is to connect the stars in the correct order. Each star has a numbering from 0 to 24, and they can be connected by dragging from the start to finish. Once mouseup event is triggered, it will compute through the big compute function to see if it's correct.

The shader code takes the position's z value (float) and converts it into vec4 (r, g, b, a) from low byte to high, so that it can be used as a pixel value which will be read from `wtf` and `gtfo` with `readPixels`. This is then re-converted to float, to 15-digits after the decimal point. The `Canvas` object has an array `d`, which is a permutation from 0 to 24; this will be used when calling `wtf` and `gtfo`.

The canvas corresponds to (-1,-1) to (1,1), where the canvas we care about is `canvas-calc`. `wtf(v0, v1, v2)` draws a rectangle with vertices `(-1,-1,d[v0]/25), (1,-1,d[v0]/25), (-1,1,d[v1]/25), (1,1,d[v1]/25)`, `d` being a permutation from 0 to 24. A point on canvas, `(width / 2, d[v2])` is taken and the z coordinate is what's passed as the z coordinate to the shader code. Essentially, `wtf` computes the `z` value at what `(width / 2, d[v2])` translates to in the shader coordinates (i.e. from (-1,-1) to (1,1)).

`gtfo(v0, v1, v2, v3, v4)` essentially does the same thing but draws one triangle with vertices `(-1, -1, (d[v0] + v0%1)/25), (3, -1, (d[v1] + v1%1)/25), (-1, 3, (d[v2] + v2%1)/25)`. Our canvas still corresponds to the same square (-1,-1) ~ (1,1), and `gtfo` computes the `z` value at what `((d[v3] + v3%1) * width / 25, (d[v4] + v4%1) * height)` corresponds to in the shader coordinates. In summary, `wtf` is a linear interpolation between two points and `gtfo` between three points.

The order in which the stars are connected are stored as an array, and some combinations of them (after being mapped through `d`) will be given as arguments to `wtf`. Some combinations of the results of these `wtf` calls will then be given to various `gtfo` calls. The sum of the results of the `gtfo` calls need to be less than `0.0001` in order to get the flag.

The deobfuscated (via https://deobfuscate.io/), renamed, and reversed script is [here](./script-deob.min.js). The renamed shader code is [here](./canvas_calc.glsl).

## Solving

We encoded the problem to SAT as follows:

A grid of 25x25 boolean variables, where `grid[x][y]` is True iff y is the x-th star in the sequence. Accordingly,
we add cardinality constraints to ensure that exactly one star is at each position in the sequence, and that each star
can only be at one position.

To generate the remaining constraints, we rely on a brute-force. First, we compute all 3-tuple values from the wtf function (25<sup>3</sup> = 15625). Then, in they we would
need to check all 15625<sup>3</sup>=~big possible inputs to gtfo. Instead, we check all pairs of 3-tuples (15625^2) and compute the value *needed* for the third 3-tuple in order to satisfy the constraint math.abs(<num> - gtfo(...)) < 10e-10 (we found we could be more restrictive than the program's 10e-5 check). To do this, we take the formula for interpolating a point on a triangle: `result = (w1 * x) + (w2 * y) + w0 * (1.0 - x - y)` and solve for w0: `w0 = target - ((w1 * x) + (w2 * y)) / (1.0 - x - y)`. If w0 is in the set of possible results from wtf, then that gives us the value for the final 3-tuple.

The brute force yields a set of 9-tuples (or, groups of 3 3-tuples) that would cause wtf() to produce the correct result. There are several 9-tuples for each; some of them are inconsistent with the problem constraints, however: for example, the first problem `(0.3837876686390533, [[11, 1, 21], [14, 1, 9], [17, 9, 21]], [16, 21])` constrains
the second value of the first tuple and the second value of the second tuple to be equal (both are star # of the second star in the sequence). After removing these, we are left with a smaller set. We [encode](https://github.com/mmm-team/public-writeups/blob/ec05ac589332cb38f185af92378366a8346cf3ba/hitcon2024/rev_revisual/solve.py#L310) all of the possiblities to SAT for each wtf call.

In the process of solving this, we initially noticed that our emulated wtf call in python was producing slightly different results. The reason was that we were taking the value at the exact coordinates of the point, [rather](https://github.com/mmm-team/public-writeups/blob/ec05ac589332cb38f185af92378366a8346cf3ba/hitcon2024/rev_revisual/solve.py#L15) than the *center* of the nearest pixel.

Solve script is [here](./solve.py).

## Credits

- @babaisflag - reversing
- @ath0 - solve script
