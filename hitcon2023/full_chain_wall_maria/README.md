# Full Chain - Wall Rose

## Overview

We are given root inside a custom qemu build that adds a custom PCI
device. The OS communicates with this device using MMIO. The device
exposes a 8192 byte memory region accessed by reading/writing to the
MMIO area.

The device state is stored in the following structure:

```c
typedef struct {
    ...
    // The fields of this struct can be read/write via MMIO.
    struct {
        uint64_t src;  // host physical address for data transfer
        uint8_t off;   // offset into buffer
    } state;
    char buff[BUFF_SIZE];  // 0x2000 buffer
    MemoryRegion mmio;
} MariaState;
```

Access to the buffer is triggered by these MMIO read/write handlers:
```
static uint64_t maria_mmio_read(void *opaque, hwaddr addr, unsigned size) {
    MariaState *maria = (MariaState *)opaque;
    uint64_t val = 0;
    switch (addr) {
        case 0x00:
            // write
            cpu_physical_memory_rw(maria->state.src, &maria->buff[maria->state.off], BUFF_SIZE, 1);
            val = 0x600DC0DE;
            break;
        case 0x04:
            val = maria->state.src;
            break;
        case 0x08:
            val = maria->state.off;
            break;
        default:
            val = 0xDEADC0DE;
            break;
    }
    return val;
}

static void maria_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size) {
    MariaState *maria = (MariaState *)opaque;
    switch (addr) {
        case 0x00:
            // read
            cpu_physical_memory_rw(maria->state.src, &maria->buff[maria->state.off], BUFF_SIZE, 0);
            break;
        case 0x04:
            maria->state.src = val;
            break;
        case 0x08:
            maria->state.off = val;
            break;
        default:
            break;
    }
}
```

## Bug

When reading to/writing from the buffer, the device always copies `BUFF_SIZE`
bytes. When the `off` field is greater than zero, this will read/write out of
the bounds of the buffer.


## Exploit

The bug allows us to read/write out of bounds of `buff` into `mmio`, which is
`MemoryRegion` object. This object contains both self-pointers and function
pointers for us to target (in particular, it contains the function pointers
that register `maria_mmio_read` and `maria_mmio_write` as read and write
handlers for this memory region):

```
struct MemoryRegion {
	...
    const MemoryRegionOps *ops;  // address of ops table in the binary
    void *opaque;  // `MariaState` pointer, used as the first argument to ops.
	...
};
```

The exploit uses the OOB read to leak `ops` and `opaque`, which, gives us the
binary address and also the address of `MariaState` (along with its
`MemoryRegion`).

It then uses the write to overwrite `ops` with a fake ops table whose write
handler points to this stack pivot gadget from the binary:
```
0x00000000007bce54 : push rax ; pop rsp ; nop ; pop rbp ; ret
```
This moves the stack to `rax`, which is equal to the `opaque` (aka the pointer
to our `MariaState`) when the gadget is called. From here, the exploit ROPs to
mprotect to gain code execution.

[qemu_escape.cc](https://github.com/mmm-team/public-writeups/blob/main/hitcon2023/full_chain_wall_maria/qemu_escape.cc)

