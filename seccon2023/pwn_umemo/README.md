# umemo

## Overview

We are given the source code for a simple memo recording binary, along
with source for a kernel module it uses.

The kernel module creates a character device at /dev/memo-tmp. The
userspace binary opens and mmaps a page of memory backed by this device.
It treats page offsets [0x100, 0x200), [0x200, 0x300), ..., [0xf00,
0x1000) as fixed memo buffers, populates [0, 0x100) with pointers to
these 15 "fixed" buffers. These memos can be read and written
arbitrarily.

In addition to these fixed buffers, the binary also supports storing in
"free space" handed out by kernel modules. These "free" buffers are
accessed by reading/writing to different user-selectable file offsets of
the file handle for the character device. The kernel module stores these
memos in a virtual buffer of `MEMOPAGE_SIZE_MAX` whose pages are lazily
allocated. This virtual buffer is the same memory that is exposed by
`mmap`ing the device file).

## Bug

The bug for this challenge was in the kernel module. As mentioned
before, access to "free space" works by reading/writing to different
offsets of a device file handle. The seek implementation verifies that
the file offset never exceeds the maximum size of the backing buffer.
```c
#define MEMOPAGE_SIZE_MAX (1 << 30)

static loff_t chrdev_seek(struct file *filp, loff_t offset, int whence){
  loff_t new_pos;

  switch(whence){
    case SEEK_SET:
      new_pos = offset;
      break;
    case SEEK_CUR:
      new_pos = filp->f_pos + offset;
      break;
    default:
      return -ENOSYS;
  }

  // Seek verifies that the file position does not exceed the maximum
  // size of the backing storage.
  if(new_pos < 0 || new_pos >= MEMOPAGE_SIZE_MAX)
    return -EINVAL;

  return filp->f_pos = new_pos;
}
```

However, the read and write handlers do not verify that the current
position plus the read/write length stays within the same limit. Below
is a snippet of the read handler. Effectively the same bug exists in the
write handler:
```c
static ssize_t chrdev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
  const struct memo *memo = filp->private_data;
  ...
  for(remain = count; remain > 0; ){
    const loff_t poff = *f_pos % 0x1000;
    const size_t len = poff + remain > 0x1000 ? 0x1000 - poff : remain;

    const char *data = get_memo_ro(memo, *f_pos);
    if(!data || copy_to_user(buf, data + poff, len))
      if(clear_user(buf, len))
        goto ERR;

    // `*f_pos* may exceed `MEMOPAGE_SIZE_MAX` here, so it is possible
    // to cause a value larger than `MEMOPAGE_SIZE_MAX` to be passed to
    // `get_memo_ro`.
    *f_pos += len;
    buf += len;
    remain -= len;
  }
    ...
}
```

The net effect of this bug is that `get_memo_ro` (and `get_memo_rw` for
writes) can be passed an offset larger than `MEMOPAGE_SIZE_MAX`.
However, the full consequences of this bug are not apparent from the
source files included with this challenge. Looking the kernel module
source included with the kmemo challenge, we see that `get_memo_ro` and
`get_memo_rw` map a file position to a memory address using a custom
page table scheme with two levels:

```c
#define MEMOPAGE_TABLE_SHIFT (9)

struct memo_page_table {
  void* entry[PAGE_SIZE/sizeof(void*)];
};

const void *get_memo_ro(const struct memo *memo, const loff_t pos){
  return __pgoff_to_memopage((struct memo *)memo, pos >> PAGE_SHIFT, false, NULL);
}

void *get_memo_rw(struct memo *memo, const loff_t pos){
  return __pgoff_to_memopage(memo, pos >> PAGE_SHIFT, true, NULL);
}

static void *__pgoff_to_memopage(struct memo *memo, const pgoff_t pgoff, const bool modable, void *new_page){
  ...
  struct memo_page_table **p_top = &memo->top;
  if(!*p_top && (!modable || !(*p_top = (void*)get_zeroed_page(GFP_KERNEL))))
    goto ERR;

  struct memo_page_table **p_med = (struct memo_page_table**)&(*p_top)->entry[(pgoff >> MEMOPAGE_TABLE_SHIFT) & ((1<<MEMOPAGE_TABLE_SHIFT)-1)];
  if(!*p_med && (!modable || !(*p_med = (void*)get_zeroed_page(GFP_KERNEL))))
    goto ERR;

  char **p_data = (char**)&(*p_med)->entry[pgoff & ((1<<MEMOPAGE_TABLE_SHIFT)-1)];
  if(modable && (!*p_data || new_page))
    *p_data = *p_data ? (free_page((uintptr_t)*p_data), new_page) : (memo->count++, (new_page ?: (void*)get_zeroed_page(GFP_KERNEL)));
  ret = *p_data;
  ...
}
```

This page table scheme can address exactly `9 + 9 + 12 = 30` bits of
address space, which is exactly `MEMOPAGE_SIZE_MAX`. This means that
when `get_memo_ro` and `get_memo_rw` receive a value greater than
`MEMOPAGE_SIZE_MAX`, the address translatoin logic wraps back around to
zero (so whatever page backing offset `n` also backs offset `n +
MEMOPAGE_SIZE_MAX`).


## Exploit

The exploit causes the program to write "free pages" at an offset of
`MEMOPAGE_SIZE_MAX - 1`, then reads and writes more than one byte from
this offset. The first byte will be read/written to offset
`MEMOPAGE_SIZE_MAX - 1`, but the bytes after will be written to the
beginning of the buffer due to wraparound. Recall that the userspace
program uses the first 0x100 bytes of this buffer to store pointers to
fixed memos. By overwriting these pointers, we can cause reads/writes of
fixed memos to read/write from arbitrary locations.

Normally, it would be trivial to solve this problem given arbitrary
read/write. However, the setup of this challenge involves interacting
with the service via running qemu in xinetd. Since qemu emulates a tty,
certain characters (most critically 0x7f) cannot be passed to the
binary's stdin.

Thus, the exploit takes great pains to avoid needing to write 0x7f or
other problematic bytes. The rough exploitation path is:

1. Use the address wraparound bug to read the 0th page containing other
   page pointers. This leaks the mmap address for the device. The base
   addresses of ld.so and libc.so are located at a consistent offset
   from the mmap address, so we get those pointers as well.
2. Leak out a stack address and the binary base address.
3. Write shellcode to the stack (this problem has an executable stack).
4. Locate the main thread's TLS area (fixed offset from ld.so base) and
   leak out glibc's pointer guard.
5. Overwrite glibc's `exit_handler` to point to the binary's bss.
6. Write a fake exit handler list in the binary's bss containing a
   mangled pointer to our shellcode address. The pointer mangling works
   to our benefit here because the mangled address will in most cases
   not contain any 0x7f bytes.

Once this is done, exiting the program will execute our shellcode.

[userland_exploit.py](userland_exploit.py)
