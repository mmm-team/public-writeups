from pwn import *

key = b''

s = '''
  *(_DWORD *)v27 = 0x7F198AB7;
  *(_DWORD *)&v27[4] = 0xF0812D54;
  *(_DWORD *)&v27[8] = 0xC9CADDB8;
  *(_DWORD *)&v27[12] = 0x3223C3D3;
  *(_DWORD *)&v27[16] = 0xAB8141BA;
  *(_DWORD *)&v27[20] = 0x2EC95302;
  *(_DWORD *)&v27[24] = 0xAD207ED6;
  *(_DWORD *)&v27[28] = 0xD295EDAB;
  *(_DWORD *)&v27[32] = 0x922AE7B6;
'''

for i in s.strip().splitlines():
    key += p32(int(i.split(' = ')[1].rstrip(';'), 0))

key += b'>'
key = bytearray(key)

handler = open('CrazyArcade.sys','rb').read()[0x850:][:0x584]

for i in range(0x1337):
    key[i%0x25] ^= (i&0xff) ^ handler[i%0x584]

print(key)
