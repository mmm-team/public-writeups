# kmemo

## Overview

We are given the source code for a kernel module implementing a memo
storage service, exposed via mmapping a character device.

This is the second part of a multi-phase pwnable starting with
exploitation of a userspace program
([umemo](https://github.com/mmm-team/public-writeups/tree/main/seccon2023/pwn_umemo))
interacting with this same kernel module.

## Bug

Recall from the umemo writeup that mmapping this kernel module's
character device exposes access to a virtual buffer whose pages are
allocated lazily.

The lazy mapping is accomplished as follows by the following code in the
module:
```c
static vm_fault_t mmap_fault(struct vm_fault *vmf){
  struct memo *memo = vmf->vma->vm_private_data;
  if(!memo)
    return VM_FAULT_OOM;

  // Looks up a page backing `pgoff`, allocating it if necessary. The
  // backing pages for the mapping are managed via a custom two-level
  // page table scheme, where pages holding page tables are allocated in
  // the same way as the pages that will be mapped here.
  char *data = get_memo_rw(memo, vmf->pgoff << PAGE_SHIFT);
  if(!data)
    return VM_FAULT_OOM;

  vmf->page = virt_to_page(data);

  return 0;
}

struct vm_operations_struct mmap_vm_ops = {
  .fault  = mmap_fault,
};

static int chrdev_mmap(struct file *filp, struct vm_area_struct *vma){
  if((vma->vm_pgoff << PAGE_SHIFT) + vma->vm_end - vma->vm_start  > MEMOPAGE_SIZE_MAX)
    return -ENOMEM;

  vma->vm_ops = &mmap_vm_ops;
  vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
  vma->vm_private_data = filp->private_data;
  vma->vm_file = filp;

  return 0;
}
```

The bug in this code comes from a fairly subtle and underdocumented
contact of `vm_operations_struct` fault handlers: when a fault handler
returns a page by populating a page in `struct vm_fault`, it is
responsible for taking a reference on the page. This reference is
released when the VMA is eventually unmapped.

Because `mmap_fault()` fails to take a reference on the returned page,
we can cause these pages to be returned to the page allocator while they
are still referenced from the device's custom page tables. This allows
a freed page (from the perspective of Linux's page allocator) to be
mapped RW into userspace.

## Exploit

Recall that the kernel module manages the backing pages its buffer with
a custom two-level page table:
```c
#define MEMOPAGE_TABLE_SHIFT (9)

struct memo_page_table {
  void* entry[PAGE_SIZE/sizeof(void*)];
};

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

At a high level, the exploit frees one of the pages stored in the last-level
page table while it is still referenced in the page table. It then
reallocates that page as a second-level table. The page now containing a
second-level page table can now be mapped into userspace and modified at
will. This gives arbitrary read/write of kernel memory.

The exploit follows this general strategy, but it operates on a number
of pages (probably unnecessarily so?) and does some searching to locate:
 - A user-mapped page containing a second level page table.
 - The offset of the mappings controlled by the user-mapped page table.

Once the exploit achieves arbitrary read/write, it locates the current
process's `struct cred` and sets its uid/gid to 0.

The [challenge author's
writeup](https://github.com/shift-crops/CTFProblemArchive/blob/master/2023/SECCON%20Online/ukqmemo/solver/exploit_lkm.c)
contains a more elengat trick that leaks the kernel text base from a
fixed IDT address without the need for any searching of memory.
