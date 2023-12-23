from pwn import *
from unicorn import *
from unicorn.x86_const import *
from capstone import *
context.arch = "amd64"

constantdata1 = bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e95bc25639f111f159a4823f92d55e1cab98aa07d8015b8312be853124c37d0c55745dbe72feb1de80a706dc9b74f19bc1c1699be48647beefc69dc10fcca10c246f2ce92daa84744adca9b05cda88f97652513e986dc631a8c82703b0c77f59bff30be0c64791a7d55163ca0667292914850ab72738211b2efc6d2c4d130d385354730a65bb0a6a762ec9c281852c7292a1e8bfa24b661aa8708b4bc2a3516cc719e892d1240699d685350ef470a06a1016c1a419086c371e4c774827b5bcb034b30c1c394aaad84e4fca9c5bf36f2e68ee828f746f63a5781478c8840802c78cfaffbe90eb6c50a4f7a3f9bef27871c6")
qwords = [u64(constantdata1[i:i+8]) for i in range(0, len(constantdata1), 8)]
qword_copy1 = "\n".join([f"movabs rbx, {hex(x)}\nmov qword ptr [rax + {hex(i*8)}], rbx" for (i, x) in enumerate(qwords)])

constantdata2 = bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b")
qwords = [u64(constantdata2[i:i+8]) for i in range(0, len(constantdata2), 8)]
qword_copy2 = "\n".join([f"movabs rbx, {hex(x)}\nmov qword ptr [rax + {hex(i*8)}], rbx" for (i, x) in enumerate(qwords)])

constantdata3 = flat({
    0x0: b"\x80",
    0x3e: b"\x40"
}, filler=b"\x00").ljust(0x40, b"\x00")

print(f"constantdata3: {constantdata3.hex()}")
qwords = [u64(constantdata3[i:i+8]) for i in range(0, len(constantdata3), 8)]
qword_copy3 = "\n".join([f"movabs rbx, {hex(x)}\nmov qword ptr [rax + {hex(i*8)}], rbx" for (i, x) in enumerate(qwords)])

# func = bytes.fromhex(func)
# print(disasm(func))
with open("asm.txt", "r") as f:
    asm_text = f.read()

asm_text = asm_text.replace("{constantdata1_moves}", qword_copy1)
asm_text = asm_text.replace("{constantdata2_moves}", qword_copy2)
asm_text = asm_text.replace("{constantdata3_moves}", qword_copy3)

asm_text_tmp = asm_text.replace("{rounded_len}", "0x40")
asm_len = len(asm(asm_text_tmp, vma=0x1000))
asm_len = (asm_len + 0xff) & ~0xff
asm_text = asm_text.replace("{rounded_len}", hex(asm_len))

func = asm(asm_text, vma=0x1000).ljust(asm_len, b"\x00")

cs = Cs(CS_ARCH_X86, CS_MODE_64)


# execute the code with unicorn

def execute():
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x1000000, 0x200000)

    # data region
    mu.mem_map(0x2000000, 0x1000)

    mu.mem_write(0x1000000, func)


    # def hook_mem_access(uc, access, address, size, value, user_data):
    #     if access == UC_MEM_READ:
    #         print(f">>> Memory is being READ at {address:#x}, data size = {size}")
        
    #     if access == UC_MEM_READ and (address > 0x2001000 or address < 0x2000000):
    #         print(f"read OOB at {hex(address)}")
    #         raise Exception("read OOB")

    # mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

    # one instruction at a time
    pc = 0x1000000
    while True:
        try:
            disass = next(cs.disasm(mu.mem_read(pc, 0x40), pc))
            print("0x%x:\t%s\t%s" %(disass.address, disass.mnemonic, disass.op_str))
            mu.emu_start(pc, pc + 0x40, count=1)
            pc = mu.reg_read(UC_X86_REG_RIP)
        except UcError as e:
            print(f"ERROR: {e}")
            break
    
    cur_hash = bytes(mu.mem_read(0x2000000, 0x20))
    return cur_hash


def execute_hash_round(input_bytes, cur_hash):
    input_bytes = input_bytes.ljust(0x40, b"\x00")
    assert len(cur_hash) == 0x20

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)

    # data region
    mu.mem_map(0x2000000, 0x1000)

    mu.mem_write(0x1000, func)

    mu.mem_map(0x3000000, 0x1000)
    mu.reg_write(UC_X86_REG_RDI, 0x3000000)
    mu.reg_write(UC_X86_REG_RSI, 0x3000000)

    mu.mem_write(0x3000000, input_bytes)
    mu.mem_write(0x3000050, cur_hash)

    # one instruction at a time
    pc = 0x1000
    while True:
        try:
            disass = next(cs.disasm(mu.mem_read(pc, 0x40), pc))
            print("0x%x:\t%s\t%s" %(disass.address, disass.mnemonic, disass.op_str))
            mu.emu_start(pc, pc + 0x40, count=1)
            pc = mu.reg_read(UC_X86_REG_RIP)
        except UcError as e:
            print(f"ERROR: {e}")
            break
    
    cur_hash = bytes(mu.mem_read(0x3000050, 0x20))
    assert cur_hash == mu.mem_read(0x2000000, 0x20)
    return cur_hash

# cur_hash = bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b")
# cur_hash = execute_hash_round(b"A" * 0x40, cur_hash)
# cur_hash = execute_hash_round(b"\x80", cur_hash)
# print(cur_hash.hex())
h = execute()
print(f"asm_len: {hex(asm_len)}")
print(base64.b64encode(func))
print(h.hex())







