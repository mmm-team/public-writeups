# CrazyArcade

The program is a modification of https://github.com/tuanngokien/Crazy-Arcade, but it uses a driver
to read and write memory in the driver via `DeviceIoControl`.

Xrefing `DeviceIoControl` shows us that the program is doing the following to decode the flag:
```
read ioctl handler bytes into handler_bytes

write magic 0x25 bytes into driver+0x3000

for i in range(0x1337):
    (driver+0x3000)[i%0x25] ^= (i&0xff) ^ handler_bytes[i%0x584]
```

Solve script in [`solve.py`](solve.py).
