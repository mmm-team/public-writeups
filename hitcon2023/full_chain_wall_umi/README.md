# Full Chain - Wall Rose

## Overview

Chaining all of our exploits from Sina (userspace pwnable), Rose (kernel
pwnable), and Maria (qemu PCI driver) together, we now able to get code
execution in a qemu process running as an unprivileged user inside of a
Docker container. However, the qemu process has a seccomp sandbox, so we
do not immediately get a full shell.

The goal is not only to get a shell, but to get a root shell within the
Docker container.

## System reconnaissance

Initially, we used the C&C shellcode and client from the Blade challenge
to inspect the machine. Unlike in the previous challenges, this
challenge brings up a long-running Docker container that can serve
multiple connections via xinetd. Since the xinetd handler script is
writable by the qemu user, we overwrote it to start a shell instead of
qemu, giving us a non-seccomp-sandboxed shell.

Inspecting the system, we notice:
 - An apache2 server running with mod\_php configured.
 - A Redis server running as root.

We did not notice there were custom sudo rules configured. Luckily, this
challenge ended up being solvable with the Redis server alone.

## Exploit

The Redis server supports modifying its configuration live. Since the
server is running as root, we reconfigured it to flush its data into
/etc/passwd. Parsing of /etc/passwd is extremely lax - as long as we get
one clean password-less entry for root, it doesn't matter if it is
surrounded by binary garbage.

Our exploit sent these commands to the Redis server:
```
set x "\nroot::0:0:root:/root:/bin/bash\n"
config set rdbcompression no
config set dir /etc
config set dbfilename passwd
save
```

This inserts a passwordless entry for root to /etc/passwd. Running `su`
then gives us a root shell.
