# lessequalmore

This program we are given implements an interpreter for a very simple VM, which is essentially [subleq](https://esolangs.org/wiki/Subleq).

## Base disassembler

First, I wrote a disassembler in Rust for the base VM instruction set

```
pub enum Opcode {
    MemSub(MemLoc, Operand),
    Print(Operand),
    JumpIfIndirectPositive(MemLoc, u64)
}

pub enum Operand {
    Mem(MemLoc),
    Read // bignum or char
}

pub struct MemLoc {
    pub addr: u64,
}
```

If the memory address operand was negative, they would use that as an indication that they should print instead of doing the memory operation. I divided each instruction into two parts: the memsub/print operation, and then the conditional jump.

The base disassembler is quite straightforward (is_negative just checks the sign bit on the u64, since i didn't want to deal with signedness):

```
pub fn disass(mem: &[u64], pc: usize) -> Vec<Opcode> {
    let val1 = mem[pc];
    let val2 = mem[pc+1];
    let val3 = mem[pc+2];

    let operand = if !is_negative(val1) {
        Operand::Mem(MemLoc { addr: val1 })
    } else {
        Operand::Read
    };

    let mut ops = vec![];
    ops.push(if !is_negative(val2) {
        Opcode::MemSub(MemLoc { addr: val2 }, operand)
    } else {
        Opcode::Print(operand)
    });

    ops.push(Opcode::JumpIfIndirectPositive ( MemLoc { addr: val2 }, val3 ));
    return ops
}
```

From here, we get ~20k lines of disassembly, and its difficult to see what is going on (or, at least *I* thought so). But there are some clear patterns. I added lifting and simplification passes to get progressively better output.

## Passes

### Control-flow simplification

The first thing you can do is eliminate conditional jumps which are going to the next instruction anyway. After doing this, you get a sense of what branch targets are actually viable, and you can start to build a CFG.

Finding all the valid code *statically* is not quite trivial, since there is a lot of self-modifying code.

### Other passes
The rest of the passes were just identifying instructions patterns which corresponded to larger macro-ops. Registers were identified (I believe there were ~8 general purpose registers, but some of the slightly higher numbers definitely also had a specific purpose).

#### `MOV [mem1] [mem2]`

Mov between memory locations or registers is accomplished via a temporary register (usually `R0`)

#### `STORE [dst], rX`

```
ZERO R0
MemSub [0x0] -= [0x1] // 0x0 - 0x426 => 0xfffffffffffffbda
ZERO [dst]
MemSub [dst] -= [0x0] // 0x0 - 0xfffffffffffffbda => 0x426
```

Puts -val in R0, then zero the destination and subtracts R0 from the destination.

#### `LOAD (indirect) [dst], [rX]`

Loads the value at memory address specified by rX, stores to `[dst]`.

This lift uses two lifted STORE operations:
```
    0x1517: STORE [0x1526], Rx
    0x1523: STORE [dst], [placeholder]
```

This was the first self-modifying instruction, since the first store (which itself is a lifted op) modifies the source of the second.

### (for other instructions, consult src/lifter.rs)

## Calling convention

```
  0x516: ZERO R1
  0x519: MOV R9, [0x515]
  0x522: ZERO R0
  0x525: ADD R1, [0x515]
  0x52b: ZERO R0
  0x52e: ADD R1, R13
  0x534: JMP [R1]
```

After some lifting steps, we find an indirect jump, relative to R13 + a constant. I found that there are tables of what appear to be jump targets at each offset where this pattern appeared.

This pattern I called VTABLEJMP.

Next we find the following pattern:

```
  0x49e: PUSH [0x4c0] (shift=[0x4a1]) // val = 0x2, offs = 0x1
  0x50c: ZERO R0
  0x50f: ZERO R1
  0x512: VTABLEJMP table at [0x515], offset R13
```

We push a constant and then make a jmp in the vtable. The pushed constant is the index in the vtable that we will return to (the return address).

For the return stack, we found R8 is the "stack pointer" and R7 is the "frame pointer":

push/pop just decrement/increment the stack (which grows down):

pop:
```
  0x1247: ADD R1, R8
  0x1250: ADD R1, R12
  0x1259: MOV R4, [R1]
  0x1271: ADD R8, [0x127a] // mem[0x127a] = 0x1
```

### 'buffer' arguments

Arguments are passed on the stack. We found a "PEEK" operation, which uses the frame pointer (R7) to access an argument on the stack:


This is `PEEK R3, [R7 + 0x2]`, which gets the second argment:

```
0x4bb0: MOV R3, R7
  0x4bbf: ADD R3, [0x4bc5] // mem[0x4bc5] = 0x2
  0x4bcc: BOUNDS_CHECK R3 R0
block_0x4be4:
  0x4be4: ADD R1, R3
  0x4bed: ADD R1, R12
  0x4bf6: MOV R3, [R1]
```

We also found a operation we call BOUNDS_CHECK which is a multi-block operation that apears before many memory accesses.

There is a further macro-op for loading/store a single element from an index in a buffer. It grabs the argument on the stack and then adds an index to it before doing a load.

This is `BUF_LOAD R3, [R7 + [0x1b68]], 0x3`

```
  0x1b53: PEEK R3, [R7 + [0x1b68]]
  0x1bb1: ADD R3, [0x1bba] // mem[0x1bba] = 0x3
  0x1bc1: BOUNDS_CHECK R3 R0
block_0x1bd9:
  0x1bd9: ADD R1, R3
  0x1be2: ADD R1, R12
  0x1beb: MOV R3, [R1]
```

## Solving the challenge 

In the end, we reduce from 20k lines of disassembly to less than 2k. Some patterns are clear: two functions compute sums of integers in the buffers. I suspect in hindsight that they are matrix-vector multiplication (but I did not check).

```
block_0x17fe:
  0x17fe: BUF_STORE [0x1887], [R7 + [0x1810]], [0x1862] // mem[0x1810] = 0x1, mem[0x1862] = 0x0
  0x18d3: BUF_LOAD R3, [R7 + [0x18e8]], [0x193a] // mem[0x18e8] = 0x2, mem[0x193a] = 0x0
  0x1983: MOV R1, R5
  0x198f: ADD R1, R12
  0x1998: MOV R4, [R1]
  0x19b0: ZERO R0
  0x19b3: ZERO R1
  0x19b6: MemSub [0x4] -= [0x3] // 
block_0x19b9:
  0x19b9: BOUNDS_CHECK R4 R0
block_0x19ce:
  0x19ce: ADD R1, R5
  0x19d7: ADD R1, R12
  0x19e0: MOV [R1], R4
  0x1a10: BUF_LOAD R3, [R7 + [0x1a25]], [0x1a77] // mem[0x1a25] = 0x2, mem[0x1a77] = 0x2
  0x1ac0: MOV R1, R5
  0x1acc: ADD R1, R12
  0x1ad5: MOV R4, [R1]
  0x1aed: ADD R4, R3
  0x1af9: BOUNDS_CHECK R4 R0
block_0x1b11:
  0x1b11: ADD R1, R5
  0x1b1a: ADD R1, R12
  0x1b23: MOV [R1], R4
  0x1b53: BUF_LOAD R3, [R7 + [0x1b68]], [0x1bba] // mem[0x1b68] = 0x2, mem[0x1bba] = 0x3
  0x1c03: MOV R1, R5
  0x1c0f: ADD R1, R12
  0x1c18: MOV R4, [R1]
  0x1c30: ZERO R0
  0x1c33: ZERO R1
  0x1c36: MemSub [0x4] -= [0x3] // 
```

Here, they compute `(-buf[0] + buf[2] + buf[3])`. They eventually compute 8 of these sums and store the result in 8 consecutive locations in memory. I wrote code to parse out these sums from the disassembly in `solve.py`. 

I noticed that the way the success string is printed is in block_0xdc1. Tracing this back, I found in func_0x79e they transform the flag in 8-byte chunks, and for each 8-byte chunk they compute the first set of sums, then overwrite the original data location, then compute + overwrite with the second set of sums. The final result (i.e. the 8-byte row of a matrix) gets stored. The whole 64-byte matrix is compared with constant data.

I used z3/claripy to solve (see solve.py).