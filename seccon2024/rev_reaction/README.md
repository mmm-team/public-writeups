# Reaction&emsp;<sub><sup>Rev, 233 points</sup></sub>

_Writeup by @ubuntor and [@bluepichu](https://github.com/bluepichu)_

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

Based on the description of the program up to this point, one of our team members recognized it as probably being an implementation of Puyo Puyo, albeit with a 14x14 board instead of the standard 6x14 board.  At this point we had a pretty good idea that the goal was to get at least a 14-chain, and then send an invalid input to end the game.

We wrote [an interactive solver](./solve.py) that lets the user interactively play the game, optionally starting by playing a log from a previous attempt.  This is based on a theoretical "correct" Puyo implementation, rather than a full reverse-engineering of the game's logic.  It turns out that this is actually different in some cases, and our first attempt at a 16-chain failed because the game handles simultaneous clears differently from an actual Puyo game.  We played a little more carefully on a second attempt and were able to finish the game and get the flag with a simple staircase 14-chain:

<video controls src="./solve.mov" />
