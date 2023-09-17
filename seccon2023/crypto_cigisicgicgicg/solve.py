from solvelinmod import solve_linear_mod

sys.path.append("dist")
from problem import *
exec(open("dist/output.txt", "r").read(), globals())

from sage.all import *

random = CIG([ICG(p1, a1, b1), ICG(p2, a2, b2), ICG(p3, a3, b3)])
block_size = random.L // 8
outputs = [int.from_bytes(leaked[i:i+block_size], "big") for i in range(0, len(leaked), block_size)]
outputs.pop() # remove last partial output
icgs = random.icgs

def inv_x(icg, x):
    return int(pow((x - icg.b) * pow(icg.a, -1, icg.p), -1, icg.p))

ts = [random.Ts[i] % icgs[i].p for i in range(3)]
L = random.L
T = random.T
equations = []
variables = {}
nout = len(outputs)
qvars = []
xvars = []
for i in range(nout):
    # o == x * t mod 2^L
    # => (q << L) + o == x * t
    qvars.append(var(f'q{i}'))
    xvars.append([])
    variables[qvars[i]] = random.T >> random.L
    for j in range(3):
        xvars[i].append(var(f'x{i}{j}'))
        variables[xvars[i][j]] = icgs[j].p
        equations.append((qvars[i] * (2 ** L) + outputs[i] == xvars[i][j] * ts[j], icgs[j].p))

qqvars = []
for i in range(nout - 1):
    # o1*o2 == (bx + a)*t*t mod 2^L
    # => ((q1*q2) << 2L) + ((q1*o2 + q2*o1) << L) + (o1*o2) == (bx + a)*t*t
    qqvars.append(var(f'qq{i}'))
    variables[qqvars[i]] = (0, ((T // 2) ** 2) >> (L * 2), (T ** 2) >> (L * 2))

    for j in range(3):
        oo = qqvars[i] * (2 ** (2 * L)) + qvars[i] * outputs[i + 1] * (2 ** L) + qvars[i + 1] * outputs[i] * (2 ** L) + outputs[i] * outputs[i+1]
        equations.append((oo == (xvars[i][j] * icgs[j].b + icgs[j].a) * ts[j] * ts[j], icgs[j].p))

result = solve_linear_mod(equations, variables, use_flatter=True)
for j in range(3):
    icg = icgs[j]
    icg.x = inv_x(icg, result[xvars[0][j]])

assert random.randbytes(300) == leaked

for j in range(3):
    icg = icgs[j]
    x = result[xvars[0][j]]
    for i in range(4):
        x = inv_x(icg, x)
    icg.x = x

print(xor(enc_flag, random.randbytes(len(enc_flag))))

# SECCON{ICG1c6iC6icgic6icgcIgIcg1C6ic6ICGICG1cGicG1C61CG1cG1c61cgIcg}
