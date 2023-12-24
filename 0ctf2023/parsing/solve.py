from collections import defaultdict
from dataclasses import dataclass, field
import re
from typing import DefaultDict, List
import subprocess
import os

START = 't_0ctf_parser::eats::eat_body0::h41e04f88113bfdc1'
END = 't_0ctf_parser::eats::eat_body599::hebca4204cd765eb9'

EDGE_RE = r".*eat_body(\d+)_(\d+)::"
NODE_RE = r".*eat_body(\d+)::"

def nodename(node):
    return node.split('::')[-2]

def parse_hlil():
    with open('./parser_1e5451a5579d477d7dd2645f30d52a89.bndb_hlil.txt', 'r') as f:
        hlil = f.read()
    
    pieces = hlil.split('\n\n')
    pieces = [p.strip() for p in pieces if p.strip() != '']

    func2save = ['eat_body', 'nom::', '::parse::', '::call_mut::']
    func_starts = [i for i, p in enumerate(pieces) if p.count('\n') == 0 and '(' in p and p.endswith(')')]
    
    funcs = {}
    for i in func_starts:
        func_name_possibilities = pieces[i].replace('(', ' ').split(' ')
        func_name_possibilities = [p for p in func_name_possibilities if len(p) > 0]
        func_name_possibilities = [p for p in func_name_possibilities if '::' in p or p.startswith('sub_')]
        if len(func_name_possibilities) != 1:
            continue
        func_name = func_name_possibilities[0]
        if not any(x in func_name for x in func2save):
            continue
        funcs[func_name] = pieces[i+1].split('\n')

    return funcs

def construct_graph(funcs):
    if os.path.exists('graph.dat'):
        from ast import literal_eval
        with open('./graph.dat', 'r') as f:
            explored = literal_eval(f.read())
    else:
        explored = {}
        queue = [START]
    
        while len(queue) > 0:
            print('>>>>>>>', len(queue), len(funcs), len(explored))
            node = queue.pop(0)
            if node in explored:
                continue
            explored[node] = []
            for line in funcs[node]:
                for func in funcs.keys():
                    if func in line:
                        explored[node].append(func)
                        queue.append(func)
    
        with open('./graph.dat', 'w') as f:
            f.write(repr(explored))

    graph = {}
    for node in explored:
        if 'eat_body' not in node:
            continue
        graph[node] = []
        queue = list(explored[node])
        while len(queue) > 0:
            next_node = queue.pop(0)
            if 'eat_body' in nodename(next_node):
                graph[node].append(next_node)
            else:
                queue += list(explored[next_node])

    return graph


funcs = parse_hlil()
graph = construct_graph(funcs)

def find_character(func):
    '''
    find characters to be matched against
    '''
    for line in func:
        if '= nom::bytes::complete::tag::' in line:
            return line.split('"')[1][:1]
    return ''

def find_score(node, func):
    overflows = [l for l in func if 'add_overflow' in l]
    if re.match(EDGE_RE, node) and '::eat_body0::' not in node and len(overflows) >= 1:
        assert len(overflows) == 1, f'multiple overflows {node} {overflows}'
        assert re.match(r".*\d+_\d+::", node)
        overflow = overflows[0].split(' ')[-1].split(')')[0]
        overflow = int(overflow, 0) - (2**32)
        score = overflow
    elif re.match(".*eat_body0::", node):
        score = 779
    elif len(overflows) == 0:
        score = 0
    else:
        assert len(overflows) == 1, f"multiple overflows {node} {overflows}"
        overflow = overflows[0].split(' ')[-1].split(')')[0]
        overflow = int(overflow, 0)
        subs = [l for l in funcs[node] if '- 0xffff' in l]
        assert len(subs) == 1
        sub = int(subs[0].split('- ')[-1], 0) - (2**32)
        score = -sub
        assert score <= 0 or len(graph[node]) == 0, f'{node}, {score}, {graph[node]}'
    return score

node_information = {}
for node in graph:
    func = funcs[node]
    node_information[node] = (find_character(func), find_score(node, func))

for node, (_, score) in node_information.items():
    if re.match(EDGE_RE, node):
        assert score < 0, f'invalid {node} {score} (edge cost always subtract)'
    if re.match(NODE_RE, node):
        assert (score > 0 and len(graph[node]) == 0) or (node == START) or (score == 0), f'invalid {node} {score} (leaf node cost always add)'

@dataclass
class EdgeInfo:
    cost: int
    node: str

@dataclass
class NodeInfo:
    char: str
    cost: int
    edges: DefaultDict[str, List[EdgeInfo]] = field(default_factory=lambda: defaultdict(list))


lgraph = {}
for node, next in graph.items():
    if re.match(NODE_RE, node):
        new_name = re.match(NODE_RE, node).group(1)
        char, score = node_information[node]
        lgraph[new_name] = NodeInfo(char, score)
        for n in next:
            assert len(graph[n]) == 1, f'invalid {node} {n} {nn} {graph[n]}'
            char, score = node_information[n]
            for nn in graph[n]:
                _edge = EdgeInfo(score, re.match(NODE_RE, nn).group(1))
                lgraph[new_name].edges[char].append(_edge)

pending = { k: 0 for k in lgraph }
for node, info in lgraph.items():
    for edge, edges in info.edges.items():
        for e in edges:
            pending[e.node] += 1

# topological sort
toposort = []
queue = [k for k, v in pending.items() if v == 0]
while len(queue) > 0:
    node = queue.pop(0)
    toposort.append(node)
    for char, edges in lgraph[node].edges.items():
        for edge in edges:
            pending[edge.node] -= 1
            if pending[edge.node] == 0:
                queue.append(edge.node)

# find path to minimize cost (maximize the value to subtract)
cost = {'0': 0}
path = {'0': 'L'}
for node in toposort:
    for char, edges in lgraph[node].edges.items():
        effective_edge_cost = 0
        for edge in edges:
            effective_edge_cost += edge.cost
            effective_edge_cost += lgraph[edge.node].cost
            if len(lgraph[edge.node].edges) > 0 or edge.node == "599":
                node_char = lgraph[edge.node].char
                new_cost = cost[node] + effective_edge_cost
                if edge.node not in cost or new_cost > cost[edge.node]:
                    cost[edge.node] = new_cost
                    path[edge.node] = path[node] + char + lgraph[edge.node].char
                break

flag = f'flag{{000000{path[re.match(NODE_RE, END).group(1)]}}}'
print (f'{flag = }')
