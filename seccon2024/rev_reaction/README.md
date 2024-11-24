## Reaction

We're given a C++ binary with symbols. (yay!)

After reversing `main` and `Environment::set()`, we notice that `main` sets up a 14x14 `vector<vector<int>>` board and `Environment::set()` generates 2 random bytes (1~4) and places them in the board based on the input we give it as follows:
```
server sends random 2 bytes
server receives 2 bytes: index, orientation

if orientation == 0:
    if pos >= 14: fail
    for i in range(2):
        index = 14-i-1
        if board[index][pos] != 0: fail
        board[index][pos] = random[i]
elif orientation == 1:
    if pos >= 14-1: fail
    for i in range(2):
        index = 14-1
        if board[index][pos+i] != 0: fail
        board[index][pos+i] = random[i]
elif orientation == 2:
    if pos >= 14: fail
    for i in range(2):
        index = 14+i-2
        if board[index][pos] != 0: fail
        board[index][pos] = random[i]
elif orientation == 3:
    if pos >= 14-1: fail
    for i in range(2):
        index = 14-1
        if board[index][pos+1-i] != 0: fail
        board[index][pos+1-i] = random[i]
```

We can dump the board before and after our input:
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal', '--window', '--']

def deref32(x):
    return x.cast(g.lookup_type('int').pointer()).dereference()

def deref64(x):
    return x.cast(g.lookup_type('long').pointer()).dereference()

p = gdb.debug('./chemic', api=True)
g = p.gdb

g.execute("break *('Environment::update()'+21)") # before Environment::set()
g.execute("break *('Environment::update()'+26)") # after Environment::set()

chars = '.1234'

# assuming static 14x14
def print_board():
    board = g.parse_and_eval('$rbx+0x18')
    num_rows = int(deref64(board+8) - deref64(board))//24
    rows = deref64(board)
    for r in range(14):
        row = deref64(rows + 24*r)
        for c in range(14):
            print(chars[int(deref32(row + 4*c))], end='')
        print()
    print('-'*14)

while True:
    g.continue_and_wait()
    print_board()
    g.continue_nowait()
    print(p.recv(2))
    p.send(b'\x01\x01')
    g.wait()
    print_board()
```

It looks like we're placing random dominos on the top row of the board, which then fall and do stuff.
