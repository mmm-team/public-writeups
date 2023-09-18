R.<x, y> = PolynomialRing(GF(2))
size = 2^8
K.<alpha> = GF(size, modulus=x^8+x^4+x^3+x^2+1)

human_world_size = 64
spirit_world_size_param = 32
disharmony_count = 16

exec(open("sample.txt", "r").read(), globals())

def decompress(x):
    if x is None:
        return K.zero()
    return alpha ^ x

synd = Matrix(K, [[decompress(x) for x in row] for row in witch_map])

# PGZ decoder to locate syndromes
v = disharmony_count
# fix y = alpha^1
row = synd[0]
# calculate coefficients of the error locator polynomial
lamb = Matrix([row[i:i+v] for i in range(v)]).solve_right(vector([-row[v+i] for i in range(v)]))
# solve for the error locations
Rk.<z> = PolynomialRing(K)
roots = (1 + sum(lamb[i] * z ^ (v - i) for i in range(v))).roots()
xs = [discrete_log(r, alpha^-1, size - 1) for r, m in roots]

# recover ys: synd[j][i] = sum((alpha ^ (k*i)) * (alpha ^ (l*j)) * (alpha ^ r[k,l]) for (k,l) in err_locs)
# ysj = [l*j + r[k,l] for (k,l) in err_locs]
ymat = Matrix([[alpha ^ (k * i) for k in xs] for i in range(1, 33)])
ys1 = [discrete_log(r, alpha, size - 1) for r in ymat.solve_right(synd[0])]
ys2 = [discrete_log(r, alpha, size - 1) for r in ymat.solve_right(synd[1])]
ys = [(b - a) % 255 for a, b in zip(ys1, ys2)]
rs = [(a - b) % 255 for a, b in zip(ys1, ys)]

# message error recovered
D = sum(((x ^ xi) * (y ^ yi) * (alpha ^ ri)) for xi, yi, ri in zip(xs, ys, rs))


import Crypto.Cipher.AES as AES
from Crypto.Util.number import long_to_bytes
import hashlib

def make_key(D):
    key_seed = b""
    for pos, value in sorted(list(D.dict().items())):
        x = pos[0]
        y = pos[1]
        power = discrete_log(value, alpha, size-1)
        key_seed += long_to_bytes(x) + long_to_bytes(y) + long_to_bytes(power)
    m = hashlib.sha256()
    m.update(key_seed)
    return m.digest()

key = make_key(D)
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(treasure_box))

# SECCON{I_te4ch_y0u_secret_spell...---number_XIV---Temperance!!!}
