from pwn import *

s = open('3ds_boy.3dsx','rb').read()

b = s[s.index(p64(0xFFFFFFFFC87881CE)):][:24*5*3]
l = []
for i in range(0, len(b), 8):
    l.append(u64(b[i:i+8], sign='signed'))
print(hexdump(b))
print(l)
