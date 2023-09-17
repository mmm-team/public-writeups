# Full Chain - Wall Rose

## Overview

We are given a simple Linux kernel module that implements a
miscellaneous devices. The devices has no real functionality apart
outside of file open and release handlers.

## Bug

The module has a heap allocated buffer that is allocated on file
open and freed on file release:
```c
#define MAX_DATA_HEIGHT 0x400

...

static char *data;

static int rose_open(struct inode *inode, struct file *file) {
    data = kmalloc(MAX_DATA_HEIGHT, GFP_KERNEL);
    if (!data) {
        printk(KERN_ERR "Wall Rose: kmalloc error\n");
        return -1;
    }
    memset(data, 0, MAX_DATA_HEIGHT);
    return 0;
}

static int rose_release(struct inode *inode, struct file *file) {
    kfree(data);
    return 0;
}

...

static struct file_operations rose_fops = {
    ...
    .open = rose_open,
    .release = rose_release,
    ...
};
```

The buffer is global, so it is not scoped to any one file. Opening the
device N times, gives you the ability to free the same 1024 byte
allocation N times.

## Exploit

We read too a little too much into the challenge README, and assumed
that the intended solution would not involve any kernel offsets. Thus,
we attempted to turn this into a use-after-free of `struct cred`
objects. The high level plan of our exploit is:

1. Open the device (this instance will be used for double freeing
   later).
2. Spray a lot of 1024 byte allocations.
3. Open the device again, allocating a 1024 byte buffer to be double-freed.
4. Spray more 1024 byte allocations.
5. Free all of the allocations. The hope is that the device buffer will
   be returned from the `kmalloc-1024` cache to the page allocator,
   where it can be reused by a different cache.
6. Spray a bunch of `struct cred` objects (which 192 bytes, allocated
   from the `cred_jar` cache) by calling `setgid(getgid())` in a bunch
   of threads. The hope is that one of these will overlap the
   freed device buffer.
7. Using the file handle from (1), free the 1024 byte buffer again
   (which if we are lucky, is now freeing a `struct cred` for one of the
   threads).
8. Allocate a lot of privileged `struct cred` objects by starting some
   processes and execing a setuid program (/bin/su).

We didn't know about this during the CTF, but this is apparently a
well-documented technique known as "DirtyCred".

At this point, if everything lines up, one of the privileged
`struct cred` objects will be allocated at the same address as the
credentials for one of the threads.

See
[kernel_exploit_unreliable.cc](https://github.com/mmm-team/public-writeups/blob/main/hitcon2023/full_chain_wall_rose/kernel_exploit_unreliable.cc)
for this exploit.

This exploit is pretty unreliable and low-quality. Among other things:
1. It fails if the thread's `struct cred` objects (192 bytes) do not
   align with the the double-freed 1024 buffer.
2. It does not take SLUB free list randomization into account.
3. It migrates an object across slab caches in a "spray-and-pray"
   fashion instead of precisely manipulating the various allocator free
   lists.

This "worked" as a quick CTF solution, but we suffered greatly from this
unreliability when performing the final full chain attack.

After the the CTF, I studied the SLUB allocator in more detail and
produced a more reliable exploit. This version of the exploit uses the
same general strategy, but migrates pages across slab caches more
precisely.

The exploit more precisely fills the slab CPU-local free list, node free
list, and CPU-local page allocator free lists with dummy allocations to
so that the slab containing the double-freed buffer can be moved from
the `kmalloc-1024` cache to the `cred_jar` cache without getting stuck
in any free lists.

Additionally, it no longer relies on the double-freed buffer aligning
with the start of a `struct cred`. Instead, after double-freeing the
buffer, the exploit filles the buffer with a thread's `struct cache`.
The then triple-frees the buffer, then fills it with a privileged
`struct cache`. This takes advantage of the fact that `kfree` will
happily add a misaligned address to a slab cache free list without any
checks.

See
[kernel_exploit_post_ctf.cc](https://github.com/mmm-team/public-writeups/blob/main/hitcon2023/full_chain_wall_rose/kernel_exploit_post_ctf.cc)
for the improved exploit.
