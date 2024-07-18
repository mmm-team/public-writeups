
import bisect
import itertools
from multiprocessing import Pool
from tqdm import tqdm
import math
import struct

from pysat.formula import CNF, IDPool
from pysat.card import CardEnc
from pysat.solvers import Solver

PIXEL_OFFSET = (0.5/650)

def round_to_pixel(x):
    assert 0.0 <= x <= 1.0
    return round(x * 650) / 650 + PIXEL_OFFSET

def fract(x):
    return x - math.floor(x)

def func1 (arg1, lo, hi):
    lo = math.floor(lo + 0.5)
    hi = math.floor(hi + 0.5)
    return math.floor((math.floor(arg1) + 0.5) / (2 ** lo)) % math.floor(1.0*(2 ** (hi - lo)) + 0.5)

def floatToVec4(g):
    orig_g = g
    if (g == 0.0):
        return 0.0 

    a = 0.0 if g > 0.0 else 1.0
    g = abs(g); 
    b = math.floor(math.log2(g))
    v3 = b + 255.0 - 128.0; 
    b = ((g / (2 ** b)) - 1.0) * pow(2.0, 23.0)
    r = v3 / 2.0; 
    v3 = fract(r) + fract(r); 
    v5 = math.floor(r); 
    r = func1(b, 0.0, 8.0) / 255.0; 
    g = func1(b, 8.0, 16.0) / 255.0; 
    b = (v3 * 128.0 + func1(b, 16.0, 23.0)) / 255.0; 
    a = (a * 128.0 + v5) / 255.0; 
    # ok now in theory we can just slap these together and get a float
    # print(f"r: {r}, g: {g}, b: {b}, a: {a}")
    res = struct.unpack('f', struct.pack('4B', int(r * 255), int(g * 255), int(b * 255), int(a * 255)))[0]
    res = round(res, 15)
    assert abs(res - orig_g) < 0.0001, f"{res} != {orig_g}"
    print(f"loss: {abs(res - orig_g)}")

    return res

# linear
def interpolate(x, source, target):
    source_min, source_max = source
    target_min, target_max = target
    assert source_min <= x <= source_max
    return (x - source_min) / (source_max - source_min) * (target_max - target_min) + target_min

# triangle
def interpolate_triangle(x, y, weights):
    # (-1, -1, (d[v0] + v0%1)/25)
    # (3, -1, (d[v1] + v1%1)/25)
    # (-1, 3, (d[v2] + v2%1)/25)

    # Normalize to 0.0-1.0
    x_norm = interpolate(x, (-1.0, 3.0), (0.0, 1.0))
    y_norm = interpolate(y, (-1.0, 3.0), (0.0, 1.0))

    assert 0.0 <= x_norm <= 0.5
    assert 0.0 <= y_norm <= 0.5

    # Now, we just do the triangle interpolation
    return weights[1] * x_norm + weights[2] * y_norm + weights[0] * (1.0 - x_norm - y_norm)

def complete_interpolated_triangle(x, y, weights, target):
    x_norm = interpolate(x, (-1.0, 3.0), (0.0, 1.0))
    y_norm = interpolate(y, (-1.0, 3.0), (0.0, 1.0))

    assert 0.0 <= x_norm <= 0.5
    assert 0.0 <= y_norm <= 0.5
    assert weights[0] == None

    weights_0 = (target - (weights[1] * x_norm + weights[2] * y_norm)) / (1.0 - x_norm - y_norm)
    return weights_0

D = [0x4, 0x14, 0x17, 0xd, 0xb, 0x0, 0xf, 0x1, 0xe, 0x15, 0x9, 0x13, 0x8, 0x3, 0x11, 0x18, 0x10, 0x6, 0x16, 0xa, 0x7, 0x12, 0x2, 0x5, 0xc]
def d(x):
    return D[int(x)]

def gtfo(v0, v1, v2, v3, v4):
    # v4, v5 should be 
    # ((d[v3] + v3%1) * width / 25, (d[v4] + v4%1) * height)
    point_x = interpolate(round_to_pixel(d(v3) / 25), (0.0, 1.0), (-1.0, 1.0))
    point_y = interpolate(round_to_pixel(d(v4) / 25), (0.0, 1.0), (-1.0, 1.0))

    # Now, we just do the triangle interpolation
    weights = ((v0 % 1 + d(v0))/25, (v1 % 1 + d(v1))/25, (v2 % 1 + d(v2))/25)
    return interpolate_triangle(point_x, point_y, weights)

def complete_gtfo(v0, v1, v2, v3, v4, target):
    # note v1/v2 already transformed into weights
    assert v0 is None
    point_x = interpolate(round_to_pixel(d(v3) / 25), (0.0, 1.0), (-1.0, 1.0))
    point_y = interpolate(round_to_pixel(d(v4) / 25), (0.0, 1.0), (-1.0, 1.0))

    weights = (None, v1, v2)
    return complete_interpolated_triangle(point_x, point_y, weights, target)

def check_gtfo(v0, v1, v2, v3, v4):
    point_x = interpolate(round_to_pixel(d(v3) / 25), (0.0, 1.0), (-1.0, 1.0))
    point_y = interpolate(round_to_pixel(d(v4) / 25), (0.0, 1.0), (-1.0, 1.0))

    # Now, we just do the triangle interpolation
    weights = (v0, v1, v2)
    return interpolate_triangle(point_x, point_y, weights)

def wtf(v0, v1, v2):
    assert int(v0) == v0
    assert int(v1) == v1
    assert int(v2) == v2

    point = round_to_pixel(d(v2) / 25)
    return interpolate(point, (0.0, 1.0), (d(v0), d(v1))) / 25

def all_tuples():
    answers = []
    m = {}
    for (a, b, c) in itertools.permutations(range(25), 3):
        w = wtf(a, b, c) * 25
        res = (w % 1 + d(w))/25
        m[(a, b, c)] = res
        answers.append(res)

    return m, answers

tuple_map, answers = all_tuples()
m = list(tuple_map.items())
print(len(m))
print(answers[1000:1010])
sorted_answers = sorted(m, key=lambda x: x[1])
assert sorted_answers[0][1] >= 0.0

def is_ok(res):
    if res < 0.0:
        return []
    # find the two closest
    idx = bisect.bisect_left(sorted_answers, res, key=lambda x: x[1])

    low = idx - 1
    while low >= 0 and abs(sorted_answers[low][1] - res) < 1e-10:
        low -= 1
    
    high = idx
    while high < len(sorted_answers) and abs(sorted_answers[high][1] - res) < 1e-10:
        high += 1
    
    num_matching = high - low - 1
    l = [sorted_answers[i][0] for i in range(low+1, high)]
    return l

    # next_lowest = sorted_answers[idx-1][1]
    # next_highest = sorted_answers[idx][1] if idx < len(sorted_answers) else sorted_answers[idx-1][1]
    # # print(f"next lowest: {next_lowest}, next highest: {next_highest}")
    # # print(f"next lowest: {next_lowest}, next highest: {next_highest} res: {res}")
    # if abs(next_lowest - res) < 1e-15:
    #     assert abs(next_highest - res) > 1e-15
    #     return sorted_answers[idx-1], abs(next_lowest - res)
        
    # if abs(next_highest - res) < 1e-15:
    #     return sorted_answers[idx], abs(next_highest - res)

    # return []

PROBLEM = [(0.3837876686390533, [[11, 1, 21], [14, 1, 9], [17, 9, 21]], [16, 21]), (0.21054889940828397, [[11, 3, 1], [11, 1, 21], [8, 11, 1]], [8, 2]), (0.475323349112426, [[11, 1, 21], [18, 11, 17], [5, 6, 10]], [0, 20]), (0.6338370887573964, [[5, 17, 2], [7, 20, 18], [5, 6, 10]], [8, 4]), (0.4111607928994082, [[11, 22, 18], [11, 3, 1], [12, 3, 10]], [23, 1]), (0.7707577751479291, [[18, 11, 17], [5, 17, 2], [16, 14, 13]], [20, 6]), (0.7743081420118344, [[23, 9, 20], [2, 11, 5], [5, 17, 2]], [9, 10]), (0.36471487573964495, [[17, 9, 21], [19, 3, 5], [20, 13, 5]], [18, 8]), (0.312678449704142, [[12, 3, 10], [23, 9, 20], [18, 11, 17]], [0, 17]), (0.9502808165680473, [[12, 15, 2], [23, 9, 20], [5, 17, 2]], [22, 10]), (0.5869052899408282, [[5, 6, 10], [9, 5, 4], [11, 22, 18]], [14, 10]), (0.9323389467455623, [[18, 11, 17], [11, 22, 18], [5, 6, 10]], [12, 7]), (0.4587118106508875, [[8, 11, 1], [2, 11, 5], [11, 22, 18]], [4, 21]), (0.14484472189349107, [[12, 3, 10], [23, 9, 20], [11, 3, 1]], [7, 15]), (0.7255550059171598, [[11, 1, 21], [18, 11, 17], [12, 15, 2]], [9, 23]), (0.5031261301775147, [[5, 17, 2], [11, 22, 18], [11, 3, 1]], [7, 1]), (0.1417352189349112, [[8, 11, 1], [11, 3, 1], [17, 9, 21]], [16, 14]), (0.5579334437869822, [[11, 3, 1], [11, 22, 18], [12, 15, 2]], [19, 11]), (0.48502262721893485, [[16, 5, 4], [20, 13, 5], [9, 5, 4]], [23, 18]), (0.5920916568047336, [[9, 5, 4], [17, 9, 21], [7, 20, 18]], [19, 6]), (0.7222713017751479, [[14, 1, 9], [11, 22, 18], [20, 13, 5]], [8, 16]), (0.12367382248520711, [[16, 5, 4], [12, 3, 10], [5, 6, 10]], [9, 5]), (0.4558028402366864, [[16, 14, 13], [16, 5, 4], [11, 22, 18]], [10, 2]), (0.8537692426035504, [[18, 11, 17], [23, 9, 20], [2, 11, 5]], [4, 11]), (0.9618170650887574, [[5, 6, 10], [12, 15, 2], [18, 11, 17]], [15, 2]), (0.22088933727810647, [[19, 3, 5], [9, 5, 4], [14, 1, 9]], [10, 5]), (0.4302783550295858, [[14, 1, 9], [16, 14, 13], [11, 1, 21]], [14, 2]), (0.6262803313609467, [[22, 0, 19], [11, 3, 1], [11, 22, 18]], [17, 22])]
NUM_PARTITIONS = 10
def thread(x):
    target, vmap, point, partition = x
    print(x)
    ok_count = 0
    good_tuples = []
    
    counter = 0
    for (i, ((inp1, a), (inp2, b)))  in enumerate(itertools.product(m, repeat=2)):
        if i % 10000000 == 0:
            print(f"partition {partition} {i} / {len(m) ** 2}")

        if (i % NUM_PARTITIONS) != partition:
            continue

        if not check_map((None, None, None), inp1, inp2, vmap):
            continue
        
        res = complete_gtfo(None, a, b, point[0], point[1], target)
        # print(f"target {target}, res: {res}")
        candidates = is_ok(res)
        if len(candidates) > 0:
            # print(f"target {target}, check: {ok}")
            # for l in candidates:
            #     check = check_gtfo(tuple_map[l], a, b, point[0], point[1])
            #     print(f"target {target}, check: {check}")
            #     print((l, a, b))
            ok_count += len(candidates)
            for c in candidates:
                good_tuples.append((c, inp1, inp2))
        else:
            pass
            # bad_tuples.append((None, inp1, inp2))

    print(f"ok count: {ok_count} {x}")
    return good_tuples

def check_map(a, b, c, v_map):
    tuples = [
        (v_map[0][0], a[0]),
        (v_map[1][0], b[0]),
        (v_map[2][0], c[0]),
        (v_map[0][1], a[1]),
        (v_map[1][1], b[1]),
        (v_map[2][1], c[1]),
        (v_map[0][2], a[2]),
        (v_map[1][2], b[2]),
        (v_map[2][2], c[2]),
    ]

    # Check that the mapping is consistent

    m = {}
    for t in tuples:
        if None in t:
            continue
        if t[0] in m:
            if m[t[0]] != t[1]:
                return False
        else:
            m[t[0]] = t[1]

    m = {}
    for t in tuples:
        if None in t:
            continue
        if t[1] in m:
            if m[t[1]] != t[0]:
                return False
        else:
            m[t[1]] = t[0]
    
    return True


def main():
    # with Pool(NUM_PARTITIONS) as p:
    #     work = [PROBLEM[26] + (i,) for i in range(NUM_PARTITIONS)]
    #     res = list(tqdm(p.imap(thread, work), total=len(work)))
    # return

    # okay = thread((PROBLEM[19][0], PROBLEM[19][2]))
    # print(len(okay))
    with Pool(100) as p:
        problems = [p + (i,) for (p, i) in itertools.product(PROBLEM, range(NUM_PARTITIONS))]
        tmp_res = list(tqdm(p.imap(thread, problems), total=len(problems)))
    
    res = []
    for i in range(0, len(tmp_res), NUM_PARTITIONS):
        x = []
        for j in range(NUM_PARTITIONS):
            x += tmp_res[i+j]
        res.append(x)
    
    print([len(x) for x in res])
    # return 
    f = CNF()
    pool = IDPool()

    # Create 25 * 25 variables, each "at most one"
    v = []
    for pos in range(25):
        # Which of the 25 stars is it?
        stars = [pool.id() for _ in range(25)]
        v.append(stars)

        f.append(stars) # at least one
        f = CNF(from_clauses=f.clauses + CardEnc.atmost(lits=stars, bound=1, vpool=pool).clauses) # at most 1
    
    for pos in range(25):
        stars = [v[i][pos] for i in range(25)]
        f = CNF(from_clauses=f.clauses + CardEnc.atmost(lits=stars, bound=1, vpool=pool).clauses) # at most 1
    
    print(f"Mapping")
    print(v)
    
    # Now we create the constraints.
    # for (prob, bad_tuples) in zip(PROBLEM, res):
    #     _, v_map, _ = prob
    #     for (a, b, c) in bad_tuples:
    #         assert a is None
    #         f.append([
    #             -v[v_map[1][0]][b[0]], -v[v_map[2][0]][c[0]],
    #             -v[v_map[1][1]][b[1]], -v[v_map[2][1]][c[1]],
    #             -v[v_map[1][2]][b[2]], -v[v_map[2][2]][c[2]],
    #         ])

    for (prob, good_tuples) in zip(PROBLEM, res):
        _, v_map, _ = prob
        options = []
        for (a, b, c) in good_tuples:
            if not check_map(a, b, c, v_map):
                continue

            option = pool.id()
            f.append([v[v_map[0][0]][a[0]], -option])
            f.append([v[v_map[1][0]][b[0]], -option])
            f.append([v[v_map[2][0]][c[0]], -option])

            f.append([v[v_map[0][1]][a[1]], -option])
            f.append([v[v_map[1][1]][b[1]], -option])
            f.append([v[v_map[2][1]][c[1]], -option])

            f.append([v[v_map[0][2]][a[2]], -option])
            f.append([v[v_map[1][2]][b[2]], -option])
            f.append([v[v_map[2][2]][c[2]], -option])

            options.append(option)
        
        if len(options) > 0:
            f.append(options) # one of the options must be true!
        else:
            print(f"no options for {prob} out of {len(good_tuples)}")
            
    
    f.to_file("test2.cnf")
    s = Solver(name='cadical195', bootstrap_with=f)
    res = s.solve()
    if res:
        print("SAT")
        path = []
        m = s.get_model()
        for (path_idx, vv) in enumerate(v):
            for (star_idx, var_id) in enumerate(vv):
                if m[var_id-1] > 0:
                    print(f"v {path_idx} {star_idx}")
                    path.append(star_idx)
        print(path)
    else:
        print("UNSAT")



if __name__ == "__main__":
    main()
    

    # print(gtfo(17.72230714559555, 7.206153124570849, 16.39307737350465, 9, 5))
    # print(gtfo(10.4030765593052, 8.005384355783475, 5.205384269356725, 8, 2))

    # 0.416123062372208
    # 0.41612307692307693
    # print(wtf(22, 12, 1))