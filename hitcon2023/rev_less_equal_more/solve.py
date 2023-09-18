from claripy import *

with open("log2.txt") as f:
    lines = f.read().split("\n")

lines1 = lines[313:]
lines2 = lines[1078:]

def do1(i1):
    last_idx = 0
    sums = [BVV(0, 24) for _ in range(8)]
    # print("Adding constraints...")
    num = 0
    sum_idx = 0
    for l in lines1:
        if "BUF_LOAD" in l:
            last_idx = int(l.split(" ")[-1], 16)
            print(f"idx: {last_idx}")
        elif "MemSub [0x4]" in l:
            sums[sum_idx] -= i1[last_idx]
            num += 1
        elif "ADD R4, R3" in l:
            sums[sum_idx] += i1[last_idx]
            num += 1
        elif "BUF_STORE" in l:
            print(f"num: {num}")
            num = 0
            sum_idx += 1
        elif "JMP [R1]" in l:
            break
    return sums

def do2(i1):
    last_idx = 0
    sums = [BVV(0, 24) for _ in range(8)]
    # print("Adding constraints...")
    num = 0
    sum_idx = 0
    for l in lines2:
        print(l)
        if "BUF_LOAD" in l:
            last_idx = int(l.split(" ")[-1], 16)
            print(f"idx: {last_idx}")
        elif "MemSub [0x4]" in l:
            sums[sum_idx] -= i1[last_idx]
            num += 1
        elif "ADD R4, R3" in l:
            sums[sum_idx] += i1[last_idx]
            num += 1
        elif "BUF_STORE" in l:
            print(f"num: {num}")
            num = 0
            sum_idx += 1
        elif "JMP [R1]" in l:
            break
    return sums

flag = [BVS("flag_%d" % i, 8) for i in range(0x40)]

data = """0x7ffff7d0c320:	0x0000000000fff438	0x0000000000000583
0x7ffff7d0c330:	0x0000000000fffc53	0x0000000000000e3e
0x7ffff7d0c340:	0x00000000000005fc	0x0000000000001933
0x7ffff7d0c350:	0x00000000000009ce	0x0000000000ffffb5
0x7ffff7d0c360:	0x0000000000fff858	0x000000000000080d
0x7ffff7d0c370:	0x0000000000fffe02	0x00000000000008d4
0x7ffff7d0c380:	0x000000000000083b	0x00000000000017ec
0x7ffff7d0c390:	0x000000000000036e	0x0000000000fffbcc
0x7ffff7d0c3a0:	0x0000000000fff883	0x000000000000055e
0x7ffff7d0c3b0:	0x0000000000fffefc	0x00000000000008a4
0x7ffff7d0c3c0:	0x0000000000000629	0x0000000000001381
0x7ffff7d0c3d0:	0x0000000000000547	0x0000000000ffff50
0x7ffff7d0c3e0:	0x0000000000fff609	0x00000000000005da
0x7ffff7d0c3f0:	0x0000000000fffcbb	0x0000000000000bf6
0x7ffff7d0c400:	0x0000000000000639	0x000000000000174e
0x7ffff7d0c410:	0x0000000000000784	0x0000000000fffe6f
0x7ffff7d0c420:	0x0000000000fff4ae	0x0000000000000353
0x7ffff7d0c430:	0x0000000000fffa53	0x0000000000000e4f
0x7ffff7d0c440:	0x00000000000002c7	0x0000000000001449
0x7ffff7d0c450:	0x0000000000000a1f	0x0000000000ffff6d
0x7ffff7d0c460:	0x0000000000fff375	0x00000000000004a5
0x7ffff7d0c470:	0x0000000000fffc5b	0x0000000000000f34
0x7ffff7d0c480:	0x000000000000055c	0x00000000000018da
0x7ffff7d0c490:	0x0000000000000b5e	0x0000000000000133
0x7ffff7d0c4a0:	0x0000000000fff801	0x0000000000000407
0x7ffff7d0c4b0:	0x0000000000fffe5e	0x000000000000097a
0x7ffff7d0c4c0:	0x0000000000000493	0x00000000000011da
0x7ffff7d0c4d0:	0x00000000000006c0	0x0000000000000021
0x7ffff7d0c4e0:	0x0000000000fff821	0x0000000000000333
0x7ffff7d0c4f0:	0x0000000000fffec2	0x0000000000000942
0x7ffff7d0c500:	0x000000000000046c	0x000000000000109f
0x7ffff7d0c510:	0x000000000000076c	0x000000000000015b"""

data = data.split("\n")
data2 = []
for d in data:
    data2.append(int(d.split()[1], 16))
    data2.append(int(d.split()[2], 16))

s = Solver()
for f in flag:
    s.add([f >= 0x20, f <= 0x7e])

# flag = [BVV(ord(x), 8) for x in "ABCDEFGHIJKLMN"]
for i in range(0, 64, 8):
    sums = do1([f.zero_extend(16) for f in flag[i:i+8]])
    sums2 = do2(sums)
    # print(sums)
    # print(sums2)
    # break
    for j in range(8):
        s.add(sums2[j] == data2[i+j])

# print(f"num: {num}")
# s.add(sum == 0)

result = s.satisfiable()
print(f"result: {result}")

result_bytes = []
for f in flag:
    result_bytes.append(s.eval(f, 1)[0])

flag_bytes = bytes(result_bytes)
print(f"flag: {flag_bytes}")


