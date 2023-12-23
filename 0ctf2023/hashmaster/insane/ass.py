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
    0x3d: b"\x06\xae"
}, filler=b"\x00").ljust(0x40, b"\x00")

print(f"constantdata3: {constantdata3.hex()}")

def generate_partial_hash_copy(buf):
    with open("copy_partial_hash.txt", "r") as f:
        copy_partial_hash = f.read()
    
    copy_partial_hash = copy_partial_hash.replace("{hash_0}", hex(u64(buf[0:8])))
    copy_partial_hash = copy_partial_hash.replace("{hash_1}", hex(u64(buf[8:16])))
    copy_partial_hash = copy_partial_hash.replace("{hash_2}", hex(u64(buf[16:24])))
    copy_partial_hash = copy_partial_hash.replace("{hash_3}", hex(u64(buf[24:32])))

    return asm(copy_partial_hash, vma=0x1000)

def inline_data(asm, name, data):
    assert len(data) % 8 == 0
    qwords = [u64(data[i:i+8]) for i in range(0, len(data), 8)]
    qword_copy = "\n".join([f"movabs rbx, {hex(x)}\nmov qword ptr [rax + {hex(i*8)}], rbx" for (i, x) in enumerate(qwords)])
    asm = asm.replace(f"{{{name}}}", qword_copy)
    return asm

def assemble_payload():
    with open("setup.txt", "r") as f:
        setup_text = f.read()
    
    with open("hash.txt", "r") as f:
        hash_text = f.read()
    
    with open("jitted.txt", "r") as f:
        jitted_text = f.read()
    
    setup_text = setup_text.replace("{constantdata1_moves}", qword_copy1)
    setup_text = setup_text.replace("{constantdata2_moves}", qword_copy1)

    template = generate_partial_hash_copy(p64(0x1337133713371337) * 4)
    assert len(template) == 0x40, f"template len: {hex(len(template))}"
    print(disasm(template))

    jitted_text = inline_data(jitted_text, "templatedata_movs", template)
    jitted_text = jitted_text.replace("{hashfunc}", hash_text)
    jitted_text = inline_data(jitted_text, "constantdata3_moves", constantdata3)

    jitted_asm = asm(jitted_text, vma=0x1000)
    print(f"jitted asm len: {hex(len(jitted_asm))}")
    jitted_asm = jitted_asm.ljust(0x600, b"\x90")
    setup_text = inline_data(setup_text, "jit_segment", jitted_asm)

    setup_asm = asm(setup_text, vma=0x1000)
    setup_aligned = (len(setup_asm) + 0x3f) & ~0x3f
    setup_asm = setup_asm.ljust(setup_aligned, b"\x90")

    print(f"setup asm len: {hex(len(setup_asm))}")
    print(hexdump(setup_asm[-0x80:]))

    with open("actual_partial_hash.bin", "rb") as f:
        actual_partial_hash = f.read()
    return setup_asm + generate_partial_hash_copy(actual_partial_hash)


# func = bytes.fromhex(func)
# print(disasm(func))
payload = assemble_payload()
# exit(1)
asm_len = len(payload)
# asm_len = ((asm_len + 0x3f) & ~0x3f) + 0x140

# func = payload.ljust(asm_len, b"\x00")
func = payload

print(hex(len(func)))

with open("payload.bin", "wb") as f:
    f.write(b"2\n")
    f.write(base64.b64encode(func) + b"\n")


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
    
    cur_hash = bytes(mu.mem_read(0x20004a0, 0x20))
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
# print(f"asm_len: {hex(asm_len)}")
print(base64.b64encode(func))
print()
print(h.hex())
print(f"{hex(len(func))}")
print(f"{hex(len(func) // 0x40)}")







