import json
OPCODES = json.load(open("custom_opcode.json"))
opmap = {c["opcode"]: (k, c) for k, c in OPCODES.items()}

f = open("bytecode.bin", "rb")

while 1:
    opc = f.read(1)
    if not opc:
        break
    opc = opc[0]
    print("0x%04x: %02x " % (f.tell(), opc), end=" ")
    if opc == 0:
        suffix = ".Wide"
        arglen = 2
        opc = f.read(1)[0]
    elif opc == 1:
        suffix = ".ExtraWide"
        arglen = 4
        opc = f.read(1)[0]
    else:
        suffix = ""
        arglen = 1

    opname, opdata = opmap.get(opc, ("UNK_%02x" % opc, {}))
    argcount = opdata.get("args_count", 0)
    argtypes = opdata.get("args", [])
    arglens = [{
        "OperandType::kRuntimeId": 2,
        "OperandType::kFlag8": 1,
    }.get(c, arglen) for c in argtypes]
    args = ", ".join(["0x" + f.read(n)[::-1].hex() for n in arglens])
    print(f"{opname}{suffix} {args}")
