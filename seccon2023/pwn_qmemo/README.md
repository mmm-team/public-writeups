# qmemo

## Overview

We are given the source code for a custom qemu PCI device. This device
implements save and load of memos to persistent storage to files outside
of the qemu VM.

Communication with this PCI device happens over a combination of MMIO,
port IO, and DMA.

This is the third part of a multi-phase pwnable which chains exploits
of:
 - A userspace program ([umemo](https://github.com/mmm-team/public-writeups/tree/main/seccon2023/pwn_umemo))
 - A kernel module ([kmemo](https://github.com/mmm-team/public-writeups/tree/main/seccon2023/pwn_kmemo))

## Bug

The state for this device is stored in the following structure in the
QEMU process:
```c
struct PCIMemoDevHdr {
  dma_addr_t sdma_addr;
  uint32_t key;
  union {
    uint32_t len;
    uint32_t pgoff;
  };
};

struct PCIMemoDevState {
  PCIDevice parent_obj;

  const bool prefetch_ram;
  const uint32_t limit_pages;

  MemoryRegion portio;
  MemoryRegion mmio;
  MemoryRegion ram;

  // Exposed via MMIO.
  struct PCIMemoDevHdr reg_mmio;
  void *addr_ram;
  uint8_t cmd_result;
  uint8_t int_flag;

  int data_fd;
  uint32_t *list_base, *list_cur;
  uint32_t key, count;
};

...

static const MemoryRegionOps pci_memodev_mmio_ops = {
  .read       = pci_memodev_mmio_read,
  .write      = pci_memodev_mmio_write,
  .endianness = DEVICE_LITTLE_ENDIAN,
  .impl = {
    .min_access_size = 1,
    .max_access_size = 4,
  },
};
```

The MMIO read and write handlers look like this:
```c
static uint64_t pci_memodev_mmio_read(void *opaque, hwaddr addr, unsigned size) {
  PCIMemoDevState *ms = opaque;
  const char *buf = (void*)&ms->reg_mmio;

  if(addr > sizeof(ms->reg_mmio))
    return 0;

  tprintf("addr:%lx, size:%d, %p\n", addr, size, &buf[addr]);

  return *(uint64_t*)&buf[addr];
}

static void pci_memodev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size) {
  PCIMemoDevState *ms = opaque;
  char *buf = (void*)&ms->reg_mmio;

  if(addr > sizeof(ms->reg_mmio)) return;

  tprintf("addr:%lx, size:%d, val:%lx\n", addr, size, val);

  *(uint64_t*)&buf[addr] = (val & ((1UL << size*8) - 1)) | (*(uint64_t*)&buf[addr] & ~((1UL << size*8) - 1));
}
```

These bounds checks of `addr` in these handlers allow read/writing up to
4 bytes (the maximum MMIO access size) past the end of `reg_mmio`.

This allows an attacker to overwrite the bottom 4 bytes of `addr_ram`,
which is a temporary buffer used when saving and restoring memos from a
file. In the device implementation, `addr_ram` is used as a temporary
buffer between DMA from the host and file IO from the qemu process.
Conveniently, it is possible to make `host_memory -> addr_ram` DMA reads
fail by specifying an invalid DMA address. When that happens, the device
will happily write data from `addr_ram` out to a saved memo file without
populating it with data from host memory.

By using the device's memo save and restore functionality, we can read
and write arbitrary data to/from `addr_ram`. This gives us arbitrary
read/write of the 4G of memory starting at `reg_mmio & ~0xffffffff`.

## Exploit

Luckily, just about all of the process's memory aside from its heap and
stack is located in the 4G region we can read/write. The exploit leaks a
libc address from a nearby page, then leaks out a glibc-mangled function
pointer and derives the pointer guard used for function pointer
mangling. It then installs an exit handler (with the necessary function
pointer mangling) to call `system(command)` when qemu exits.

The exploit cause qemu to exit on its own. Despite searching for a few
minutes the author was not able to find a trivial way to cause qemu to
exit, even as root (the kernel did not appear to have the sysrq triggers
compiled in). Instead, we rely on the previous exploit in the "full
chain" (the kmemo exploit) to crash the kernel and cause qemu to exit.
Exiting the root shell spawned by the kmemo exploit is sufficient to
kill qemu and spawn a shell from the qemu process.

This is one of the rare times we have been rewarded for writing a crashy
exploit that doesn't clean up properly after itself :-)

Exploit code: [qemu_exploit.cc](https://github.com/mmm-team/public-writeups/blob/main/seccon2023/pwn_qmemo/qemu_exploit.cc)
