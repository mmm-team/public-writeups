# Parsing (Revering, 500 points)
> Solved by @5w1Min, @f0xtr0t, @bluepichu

Parsing was a reversing challenge solved by 12 teams.

## Description
> An unremarkable FLAG [parser](./parser_1e5451a5579d477d7dd2645f30d52a89).

## Overview
```
./parser_1e5451a5579d477d7dd2645f30d52a89 "asdf"
Invalid Header
./parser_1e5451a5579d477d7dd2645f30d52a89 "flag{}"

```

We were given a **not stripped** rust binary. It accepts string from argument and print out *Invalid Header*, nothing, *You cannot pass!*, or *pass* based on the input. Our task is to find out the input string to print out *pass*.

## Reverse
The program use parser library, [nom](https://docs.rs/nom/), to parse the input from argument.

With a bit of reversing, the goal is to have `t_0ctf_parser::eats::SCORE`, which is initialized to 779, larger than 0 at the end.

First 6 characters will be parsed as 3 set of 2 hexadecimal integers, in function `t_0ctf_parser::eats::eat_body0`, sum it up and substract from `SCORE`.

Also, two types of the functions caught our attention:
- `t_0ctf_parser::eats::eat_body{num}`
    - compare the next byte of the input string
    - if matched
        - subsequent calls to `t_0ctf_parser::eats::eat_body{num}_{num#?}`
- `t_0ctf_parser::eats::eat_body{num#1}_{num#2}`
    - a children from `t_0ctf_parser::eats::eat_body{num#1}`
    - compare the next byte of the input string
    - if matched
        - call `t_0ctf_parser::eats::eat_body{num#2}`
        - substract certain amount from `t_0ctf_parser::eats::SCORE`

Therefore, all these functions can be use to construct a [directed ayclic graph](./call_graph.svg) such that `t_0ctf_parser::eats::eat_body{num}` as nodes and `t_0ctf_parser::eats::eat_body{num#1}_{num#2}` as edges.

After a little bit more digging, we can find that some of the edges from the same nodes try to match the **same character** and all these edges will first try to match to leaf nodes, backtrack, and the last one will always be an internal nodes.

**Does leaf nodes behavave any differently and which of the leaf node is our target?**

Leaf nodes can be separated into two types:
- `599` (target)
    - lead to `t_0ctf_parser::eats::eat_tail`, that try to match the `}` from the input
    - That is, our input string should be able to reach here
- others
    - lead to `t_0ctf_parser::eats::die` if the input string match the character
    - before matching the input, **add** certain amount to `t_0ctf_parser::eats::SCORE`

That is, all the leaf nodes, except `599`, will create an positive impact to the `SCORE` and by comparing the being added here to the edges, the amount of addition are always larger than the final substraction value. Hence, whenever an internal node with edges of same character, **we should always pick such character to have a positive impact on the** `SCORE`.

## Solution
Extract all the information (value to be apply on score and character to match for each function) from [dump file](./parser_1e5451a5579d477d7dd2645f30d52a89.bndb_hlil.txt).

Find a path from *node 0* to *node 599* that minimize the cost.

All this is done in the python [script](./solve.py).

The path found has a cost of 778 so the leading hex digits should be `000000`.

```
./parser_1e5451a5579d477d7dd2645f30d52a89 "flag{000000Ly7PbxKgm3\!8gJXUHTLqjj311j6gSyMJHg7apxCM0lR_y5b9g2cvOW\!_gnoQVms69Hf6Af63NvabnOHndAgQi}"
pass
```
