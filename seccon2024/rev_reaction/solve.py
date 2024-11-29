from pwn import *
from time import strftime, sleep
import sys

replay_path = sys.argv[1] if len(sys.argv) > 1 else None
replay_file = open(replay_path, "rb") if replay_path else None

# Connect to the server
r = remote("reaction.seccon.games", 5000)
log = open(f"logs/{strftime('%Y-%m-%d_%H-%M-%S')}.log", "wb")

board = [[None for _ in range(14)] for _ in range(14)]

colors = [
	None,
	"\x1b[41m \x1b[0m",
	"\x1b[42m \x1b[0m",
	"\x1b[43m \x1b[0m",
	"\x1b[44m \x1b[0m",
]

faded = [
	None,
	"\x1b[31mR\x1b[0m",
	"\x1b[32mG\x1b[0m",
	"\x1b[33mY\x1b[0m",
	"\x1b[34mB\x1b[0m",
]

def get_locs(x, o):
	if o == 0:
		return [(13, x), (12, x)]
	elif o == 1:
		return [(13, x), (13, x+1)]
	elif o == 2:
		return [(12, x), (13, x)]
	elif o == 3:
		return [(13, x+1), (13, x)]

def get_drop_loc(r, c):
	for nr in range(r-1, -1, -1):
		if board[nr][c] is not None:
			return nr + 1, c
	return 0, c

def render_board(a, b, x, o):
	# clear the screen
	print("\033[H\033[J")
	if a is not None:
		aloc, bloc = get_locs(x, o)
		if aloc[0] <= bloc[0]:
			adloc = get_drop_loc(*aloc)
			board[adloc[0]][adloc[1]] = 5
			bdloc = get_drop_loc(*bloc)
			board[adloc[0]][adloc[1]] = None
		else:
			bdloc = get_drop_loc(*bloc)
			board[bdloc[0]][bdloc[1]] = 5
			adloc = get_drop_loc(*aloc)
			board[bdloc[0]][bdloc[1]] = None
	else:
		aloc = bloc = adloc = bdloc = None
	for r, row in list(enumerate(board))[::-1]:
		print("X", end="")
		for c, cell in enumerate(row):
			fade = False
			if aloc is not None:
				if (r, c) == aloc:
					cell = a
				elif (r, c) == bloc:
					cell = b
				elif (r, c) == adloc:
					cell = a
					fade = True
				elif (r, c) == bdloc:
					cell = b
					fade = True
			if cell is None:
				print(" ", end="")
			else:
				if fade:
					print(faded[cell], end="")
				else:
					print(colors[cell], end="")
		print("X")
	print("> ", end = "")

def flood(r, c):
	assert board[r][c] is not None
	matched = {(r, c)}
	stack = [(r, c)]
	while stack:
		r, c = stack.pop()
		for dr, dc in [(0, 1), (0, -1), (1, 0), (-1, 0)]:
			nr, nc = r + dr, c + dc
			if 0 <= nr < 14 and 0 <= nc < 14 and board[nr][nc] == board[r][c] and (nr, nc) not in matched:
				matched.add((nr, nc))
				stack.append((nr, nc))
	return matched

def simulate():
	chain_len = 0
	while True:
		# drop all pieces as far as possible
		dropped = False
		for c in range(14):
			next_r = 0
			for r in range(14):
				if board[r][c] is not None:
					board[next_r][c] = board[r][c]
					if r != next_r:
						board[r][c] = None
						dropped = True
					next_r += 1
		if dropped:
			render_board(None, None, None, None)
			print("Chain length:", chain_len)
			sleep(0.1)
		# clear groups of 4+
		chained = False
		for r in range(14):
			for c in range(14):
				if board[r][c] is not None:
					matched = flood(r, c)
					if len(matched) >= 4:
						chained = True
						for r, c in matched:
							board[r][c] = None
		if chained:
			chain_len += 1
			render_board(None, None, None, None)
			print("Chain length:", chain_len)
			sleep(0.1)
		else:
			break

	print("Chain length:", chain_len)

while True:
	# Server provides two bytes
	a, b = r.recv(2)
	if a > 4:
		# receive as much as possible
		out = r.recvline()
		out = bytes([a, b]) + out
		print(out)
		break

	x = 0
	o = 0

	while True:
		render_board(a, b, x, o)
		if replay_file is not None:
			server_inp = replay_file.read(2)
			if not server_inp:
				replay_file.close()
				replay_file = None
			else:
				x, o = server_inp
				break
		inp = input().upper()
		if inp == "D": # right
			x += 1
			if x >= 13:
				x = 13
		elif inp == "A": # left
			x -= 1
			if x < 0:
				x = 0
		elif inp == "S": # rotate
			o += 1
			if o >= 4:
				o = 0
		elif inp == "": # submit
			break
		elif inp == "Q":
			x = 9
			o = 9
			break

	server_inp = bytes([x, o])
	r.send(server_inp)
	log.write(server_inp)
	log.flush()

	if x == 9 and o == 9:
		break

	# Update the board
	aloc, bloc = get_locs(x, o)
	board[aloc[0]][aloc[1]] = a
	board[bloc[0]][bloc[1]] = b
	simulate()

output = r.recvall()
print(output)
