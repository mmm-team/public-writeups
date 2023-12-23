# BabyKitDriver

BabyKitDriver is a macOS kernel exploitation challenge with a custom buggy IOKit driver.

> qemu+macOS ventura 13.6.1
>
> upload your exploit binary and the server will run it for you, you can get the output of your exploit.
>
> the flag is at /flag
>
> Just pwn my first IOKit Driver!
>
> nc baby-kit-driver.ctf.0ops.sjtu.cn 20001
>
> [attachment](./BabyKitDriver.kext_D5ED88B9E517723BF57C28E742D3AE49.zip)


BabyKit provides two external methods - `baby_read` and `baby_leaveMessage` and can be used to store or retrieve messages in two different format - fixed and variable length (max `512` bytes).
The structure (reconstructed by reversing) used to save the buffer is as follows, and there is only one per instance.

```c
union msg_t {
    struct {
        uint64_t size;
        void (*fnptr)(char *, char *, uint64_t);
        uint8_t buf[0];
    } variable;

    struct {
        void (*fnptr)(char *, char *);
        uint8_t buf[0];
    } fixed;

    uint8_t _buf[0x300];
};
```

# Setup

We used the following to get a proper debugging support of XNU:

1. Download the installer using `softwareupdate`
2. Convert the `InstallAssistant.pkg` file to an `.iso`. I used the following [link](https://osxdaily.com/2020/07/20/how-convert-macos-installer-iso/).
3. Create new VMWare VM and install the OS
4. Disable SIP. This requires going into recovery mode which is not fun.
  - Had to set nvram `internet-recovery-mode` and/or `recovery-boot-mode` because the original key were not detected by bios.
  - Also adding `bios.bootDelay` in vmx file is helpful.
5. Follow along [hex-rays blog](https://hex-rays.com//wp-content/static/tutorials/xnu_debugger_primer/xnu_debugger_primer.html) or [their whitepaper pdf](https://hex-rays.com//wp-content/uploads/2020/05/mac_debugger_primer2.pdf).

This gave us a really helpful setup to set breakpoint and continue from it while debugging our exploit.

# Bug

Few bugs were identified in the driver that were use during exploitation:

1. Size checks are signed in `baby_leaveMessage` and `baby_read` for variable message versions.
  - signed check in `baby_leaveMessage` allows setting any negative `int64_t` value
  - signed check in `baby_read` allows giving a size that is a negative value

2. `baby_leaveMessage` and `baby_read` operate on the same global data structure without any atomicity. This results in a race because `baby_read` checks the version to find how to parse the buffer structure while `baby_leaveMessage` will update version at the end after setting up the buffer structure in memory. Thus a thread doing `baby_read` while another thread is processing `baby_leaveMessage` can end up reading old version value/type.

# Exploit

At high level, exploitation for this step was to first leak the kernelcache address, followed by setting up the buffer for a ROP and using the race condition to pivot stack to the heap buffer.

1. Initialize the setup by getting the relevant `BabyKitDriver` IOService.
2. Use the signed check on size bug to provide a high negative value to read the stack during `baby_read`.
3. Create a ROP chain that will be placed in the heap memory
4. Use race condition bug to basically have the thread interleaving as follows, leading to a ROP chain execution.

```
+---------------------------+---------------------------+
|Thr1                       | Thr2                      |
+---------------------------+---------------------------+
|   msg_version = variable  |                           |
|                           |                           |
| baby_leaveMessage:        | baby_read:                |
|   variable.size = <kaddr> |                           |
|   copyin(...)             |                           |
|   ...                     |                           |
|                           |   version = msg_version   |
|                           |   ....                    |
|                           |   call_fnptr(...)         |
|   msg_version = fixed     |                           |
```

5. On a successful race, we use thread1 to read flag file while other (thread2) is infinitely spinning in the kernel.

The overall idea of the ROP chain used to gain privileges was the following:
1. get credential structure by calling `proc_ucred` on current process/task (`current_proc`)
2. call `zalloc_ro_clear` with controlled arguments to memset the cred structure to `0` (root). This is required because creds structure are allocated using the ro allocator in XNU, thus the address is marked as read-only.
3. Do infinite loop in XNU while another thread reads the flag. We tried `thread_exception_return` initially, but `IOUserClient::externalMethod` holds the read lock, which either needs to be released or the lock count in thread structure needs to be reset. Thus we decided to take easy way out by looping in the end.

Please looking at the [exploit file](./exp.c) for more details.

NOTE: Requires multiple attempt since our failure rate of winning the race is high.

flag: `flag{7ac21f7848a39f0aea63fa29d304226a}`
