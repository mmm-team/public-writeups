class HighDensityException(Exception):
    pass


class LOAttack:

    def __init__(self, array, target_sum, try_on_high_density=False):
        self.array = array
        self.n = len(self.array)
        self.target_sum = target_sum
        self.density = self._calc_density()
        self.try_on_high_density = try_on_high_density

    def _calc_density(self):
        return self.n / log(max(self.array), 2)

    def _check_ans(self, ans):
        calc_sum = sum(map(lambda x: x[0] * x[1], zip(self.array, ans)))
        return self.target_sum == calc_sum

    def solve(self):
        if self.density >= 0.6463 and not self.try_on_high_density:
            raise HighDensityException()

        # 1. Initialize Lattice
        L = Matrix(ZZ, self.n + 1, self.n + 1)
        N = ceil(self.n ^ 0.5 / 2)
        for i in range(self.n + 1):
            for j in range(self.n + 1):
                if j == self.n and i < self.n:
                    L[i, j] = N * self.array[i]
                elif j == self.n:
                    L[i, j] = N * self.target_sum
                elif i == j:
                    L[i, j] = 1
                else:
                    L[i, j] = 0

        # 2. LLL!
        B = L.LLL()

        # 3. Find answer
        for i in range(self.n + 1):
            if B[i, self.n] != 0:
                continue

            if all(-1 <= v <= 0 for v in B[i]):
                ans = [-B[i, j] for j in range(self.n)]
                if self._check_ans(ans):
                    return ans

        # Failed to find answer
        return None


subset_arr = [0x38ED550C61366B19, 0xA368D7F6F944EF95, 0x7730E544811B003B, 0xBA7B915F29478B8, 0x4CF3C7A1444DDCD5, 0x6A1EE5D1CB932EDD, 0x1C653D0FAA75CD04, 0x5129602CEBB27CD3, 0x8D3E0DDB822D166C, 0x7743085C81B563CA, 0x1FD73D5B1682BEC1, 0x49CA0C91D932E680, 0x10AC7806FD7DC9E2, 0x939CB3D71DC3703E, 0x3719C10EFED548AF, 0x91AAD1F7FE14E4B, 0x8FE8985576B03857, 0x376937BC0AF64E77, 0x26190529FD5F0437, 0x12CF894F2AF71BF3, 0x22E8F33E31870D59, 0x6842E8D2ED57A1F1, 0x189EBE5A06E8334F, 0x591CEA928108D643, 0x4914740091A11C11, 0x3B1A8BB8CD64FAE1, 0x48009C01B6DC47BA, 0x6CC80ED5A2D94B80, 0x3A41F29B470B9346, 0x154D52272BF8F, 0x7E416B359A0655CC, 0x6858E18B590D1A8F, ]
subset_target = 0x6B3312EC731522288
inp12 = LOAttack(subset_arr, subset_target).solve()
inp12 = int(''.join(str(i) for i in inp12[::-1]), 2)

arr = [0xAEC4F08C & 2**32-1, 0x642C04AC & 2**32-1, -1553958828 & 2**32-1, 758724916 & 2**32-1, -1909698726 & 2**32-1, -573145836 & 2**32-1, 2113950870 & 2**32-1, 1053903362 & 2**32-1, 173451122 & 2**32-1, 1181368438 & 2**32-1, -744271191 & 2**32-1, 1230935011 & 2**32-1, 1740917471 & 2**32-1, 988538298 & 2**32-1, -310047320 & 2**32-1, -726175336 & 2**32-1, 1371387570 & 2**32-1, 979313736 & 2**32-1, -2139584054 & 2**32-1, 1537035630 & 2**32-1, -2094993450 & 2**32-1, -1637291916 & 2**32-1, -1166033247 & 2**32-1, -2105817116 & 2**32-1, 312443466 & 2**32-1, ]

rol = lambda x, y: ((x << y) | (x >> (32 - y))) & 2**32-1

pow_arr = [2731294519, 3098600166, 2649378774, 2306711766, 1387684069, 2109529097, 1485731894, 1051166437, 1539816243, 2744491654, 1521506863, 0xB09E4A8C, ]
F = GF(0xE53ACEB5)
for i in range(len(pow_arr)):
    pow_arr[i] = int(F(pow_arr[i]).log(0x56361E32))

quo_arr = [467908244, 181677961, 0x1003913B7, 935476916, 1690337013, 226183045, 1225873732, 1380054110, 2190942953, 1744947825, 374350031, 3831462577, ]

mul_arr = []
for i in range(12):
    mul_arr.append(quo_arr[i] * inp12 + pow_arr[i])

flag_arr = [0 for i in range(25)]
flag_arr[12] = inp12

for i in range(12):
    factors, _ = zip(*factor(mul_arr[i]))
    a, b = min(factors), max(factors)
    if i < 6:
        flag_arr[i * 2] = a
        flag_arr[i * 2 + 1] = b
    else:
        flag_arr[-(i - 6) * 2 - 1] = a
        flag_arr[-(i - 6) * 2 - 2] = b


flag = b''
for i in range(len(flag_arr)):
    flag_arr[i] ^^= arr[i] ^^ 0xCAFEBABE
    for j in range(26):
        flag_arr[i] = rol(flag_arr[i], 32-25) ^^ 0x14530451
    flag_arr[i] = rol(flag_arr[i], 32-25) ^^ 0xDEADBEEF
    import struct
    flag += struct.pack(">L", flag_arr[i])

print(flag)



