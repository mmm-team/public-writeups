from pwn import *

e = ELF('jumpout')
x1 = e.read(0x4010, 32)
x2 = e.read(0x4030, 32)
print(x1, x2)

flag = ''
for i in range(0x1d):
    flag += chr(x1[i]^0x55^i^x2[i])
print(flag) 
