
use crate::disass::*;
use std::fmt;
use std::collections::{VecDeque, HashMap};
use itertools::Itertools;

#[derive(Clone)]
pub struct LiftedOp {
    pub opc: LiftedOpcode,
    pub pc: usize,
}

#[derive(Clone)]
pub enum LiftedOpcode {
    Jmp(u64),
    Add(LiftedOperand, LiftedOperand),
    Mov(LiftedOperand, LiftedOperand),
    Store(MemLoc, LiftedOperand),
    Zero(LiftedOperand),
    JmpIndirect(LiftedOperand),
    VtableJmp(u64, LiftedOperand),
    Call(u64, LiftedOperand), // LiftedOperand is the return address!!!
    Jeq(LiftedOperand, LiftedOperand, u64, u64),
    Jne(LiftedOperand, LiftedOperand, u64, u64),

    BoundsCheck(LiftedOperand, LiftedOperand), // value, max

    // Argument passing
    Push(LiftedOperand, LiftedOperand), // value, stack_shift_amount
    Pop(LiftedOperand, LiftedOperand), // value, stack_shift_amount
    Peek(LiftedOperand, LiftedOperand), // dst, local_off (relative to frame base)

    // When arguments are pointers, this is how to access elements (local_off is used in a Peek)
    PeekBufLoad(LiftedOperand, LiftedOperand, LiftedOperand), // dst, local_off, index
    PeekBufStore(LiftedOperand, LiftedOperand, LiftedOperand), // src, local_off, index

    Unlifted(AnnotatedOpcode),
}

impl LiftedOpcode {
    pub fn vtable_targets(&self, mem: &[u64], aggressive: bool, include_return: bool) -> Vec<usize> {
        let mut targets = vec![];
        if let LiftedOpcode::VtableJmp(table_addr, _) | LiftedOpcode::Call(table_addr, _) = self {
            let table_base = mem[13] + mem[*table_addr as usize];
            let mut idx = 0;
            loop {
                let fptr = mem[table_base as usize + idx];
                if fptr == 0 { break; }
                // println!("vtable[{}] = {:#x}", i, fptr);
                targets.push(fptr as usize);
                idx += 1;
                if !aggressive {
                    break;
                }
            }
        }

        if include_return {
            if let LiftedOpcode::Call(_, LiftedOperand::Mem(MemLoc { addr: a })) = self {
                let return_slot = mem[*a as usize];
                let table_base = mem[13] + return_slot;
                let fptr = mem[table_base as usize];
                targets.push(fptr as usize);
            }
        }
        return targets;
    }

    pub fn comment(&self, mem: &[u64]) -> Option<String> {
        if let Some((c_src, c)) = match self {
            LiftedOpcode::Mov(LiftedOperand::Reg(_), LiftedOperand::Mem(MemLoc { addr: a }))
            | LiftedOpcode::Add(LiftedOperand::Reg(_), LiftedOperand::Mem(MemLoc { addr: a })) => {
                let a = *a as usize;
                mem.get(a).cloned().map(|x| (a, x))
            },
            LiftedOpcode::Unlifted(op) => {
                match op.opc {
                    Opcode::MemSub(_, Operand::Mem(MemLoc { addr: b })) => {
                        if b >= 0xe {
                            mem.get(b as usize).cloned().map(|x| (b as usize, x))
                        } else { None }
                    },
                    _ => None
                }
            },
            LiftedOpcode::Jne(_, LiftedOperand::Mem(memloc), _, _) | LiftedOpcode::Jeq(_, LiftedOperand::Mem(memloc), _, _) => {
                if let Some(c) = mem.get(memloc.addr as usize) {
                    return Some(format!(" // mem[{:#x}] = {:#x}", memloc.addr, c));
                }
                None
            },
            _ => None
        } {
            return Some(format!(" // mem[{:#x}] = {:#x}", c_src, c));
        }

        match self {
            LiftedOpcode::PeekBufLoad(data, buf, idx) | LiftedOpcode::PeekBufStore(data, buf, idx) => {
                if let (LiftedOperand::Mem(MemLoc { addr: a1 }), LiftedOperand::Mem(MemLoc { addr: a2 })) = (buf, idx) {
                    if let (Some(src_val), Some(dst_val)) = (mem.get(*a1 as usize), mem.get(*a2 as usize)) {
                        if let LiftedOperand::Mem(MemLoc { addr: a3 }) = data {
                            if let Some(data_val) = mem.get(*a3 as usize) {
                                return Some(format!(" // mem[{:#x}] = {:#x}, mem[{:#x}] = {:#x}, data: mem[{:#x}] = {:#x}", a1, src_val, a2, dst_val, a3, data_val));
                            }
                        }
                        return Some(format!(" // mem[{:#x}] = {:#x}, mem[{:#x}] = {:#x}", a1, src_val, a2, dst_val));
                    }

                }
            },
            LiftedOpcode::Push(val, off) | LiftedOpcode::Pop(val, off) => {
                let val = match val {
                    LiftedOperand::Mem(MemLoc { addr: a }) => {
                        mem.get(*a as usize)
                    },
                    _ => None
                };
                let offs = match off {
                    LiftedOperand::Mem(MemLoc { addr: a }) => {
                        mem.get(*a as usize)
                    },
                    _ => None
                };
                return Some(format!(" // val = {:#x}, offs = {:#x}", val.unwrap_or(&0), offs.unwrap_or(&0)));
            }
            _ => {}
        };

        None
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum LiftedOperand {
    Mem(MemLoc),
    IndirectMem(u8),
    Reg(u8),
    Input,
}

impl LiftedOperand {
    pub fn from_operand(op: &Operand) -> LiftedOperand {
        match op {
            Operand::Mem(m) => {
                match m.get_reg() {
                    Some(r) => LiftedOperand::Reg(r),
                    None => LiftedOperand::Mem(m.clone()),
                }
            }
            Operand::Read => LiftedOperand::Input,
        }
    }
}

impl fmt::Debug for LiftedOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiftedOperand::Mem(x) => x.fmt(f),
            LiftedOperand::IndirectMem(x) => write!(f, "[R{}]", x),
            LiftedOperand::Reg(x) => write!(f, "R{}", x),
            LiftedOperand::Input => write!(f, "input()")
        }
    }
}

impl fmt::Debug for LiftedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}: {:?}", self.pc, self.opc)
    }
}
impl fmt::Debug for LiftedOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiftedOpcode::Jmp(x) => write!(f, "JMP {:#x}", x),
            LiftedOpcode::JmpIndirect(x) => write!(f, "JMP {:?}", x),
            LiftedOpcode::Jeq(x, y, target1, target2) => write!(f, "Jeq {:?} == {:?} block_{:#x} block_{:#x}", x, y, target1, target2),
            LiftedOpcode::Jne(x, y, target1, target2) => write!(f, "Jne {:?} != {:?} block_{:#x} block_{:#x}", x, y, target1, target2),
            LiftedOpcode::VtableJmp(table, off) => write!(f, "VTABLEJMP table at [{:#x}], offset {:?}", table, off),
            LiftedOpcode::Call(table, off) => write!(f, "CALL table at [{:#x}], return slot {:?}", table, off),
            LiftedOpcode::Add(dst, src) => write!(f, "ADD {:?}, {:?}", dst, src),
            LiftedOpcode::Mov(dst, src) => write!(f, "MOV {:?}, {:?}", dst, src),
            LiftedOpcode::Store(dst, src) => write!(f, "STORE {:?}, {:?}", dst, src),
            LiftedOpcode::Zero(dst) => write!(f, "ZERO {:?}", dst),
            LiftedOpcode::BoundsCheck(x, y) => write!(f, "BOUNDS_CHECK {:?} {:?}", x, y),
            LiftedOpcode::Peek(x, y) => write!(f, "PEEK {:?}, [R7 + {:?}]", x, y),
            LiftedOpcode::Push(x, s) => write!(f, "PUSH {:?} (shift={:?})", x, s),
            LiftedOpcode::Pop(x, s) => write!(f, "POP {:?} (shift={:?})", x, s),

            LiftedOpcode::PeekBufLoad(dst, buf, idx) => write!(f, "BUF_LOAD {:?}, [R7 + {:?}], {:?}", dst, buf, idx),
            LiftedOpcode::PeekBufStore(src, buf, idx) => write!(f, "BUF_STORE {:?}, [R7 + {:?}], {:?}", src, buf, idx),
            LiftedOpcode::Unlifted(x) => x.fmt(f)
        }
    }
}
pub struct Lifter<'a> {
    pub instruction_stream: Vec<LiftedOp>,
    replacements_per_pass: &'a mut HashMap<&'static str, usize>,
}

pub fn check_opaque_jump(ops: &[Opcode]) -> bool {
    for window in ops.windows(2) {
        if let (Opcode::MemSub(MemLoc { addr: 0 }, Operand::Mem(MemLoc { addr: 0 })), Opcode::JumpIfIndirectPositive(MemLoc { addr: 0 }, target)) = (&window[0], &window[1]) {
            return true;
        }
    }
    return false;
}

impl<'a> Lifter<'a> {
    pub fn new(insns: &[AnnotatedOpcode], stats: &'a mut HashMap<&'static str, usize>) -> Lifter<'a> {
        Lifter {
            instruction_stream: insns.iter().map(|x|
                LiftedOp { opc: LiftedOpcode::Unlifted(x.clone()), pc: x.pc }
            ).collect(),
            replacements_per_pass: stats
        }
    }
    pub fn new_for_cross_block_lifts(insns: Vec<LiftedOp>, stats: &'a mut HashMap<&'static str, usize>) -> Lifter<'a> {
        Lifter {
            instruction_stream: insns,
            replacements_per_pass: stats
        }
    }
    pub fn lift(&mut self) {
        self.remove_bogus_jumps();
        self.jumps();
        self.lift_zero();
        self.lift_mov();
        self.lift_store();
        self.lift_store_indirect_1();
        self.lift_zero_add();
        self.lift_store_indirect_2();
        self.lift_indirect_jump();
        self.lift_mov_mem_indirect();
        self.lift_jumptable();
    }

    pub fn cross_block_lifts(&mut self) {
        self.remove_redundant_zeroes();
        self.lift_assert1();
        self.remove_unnecessary_jumps();
        self.remove_redundant_zeroes();
        self.lift_push();
        self.lift_pop();
        self.lift_peek();
        self.lift_buf_load();
        self.lift_buf_store();
        self.lift_call();
        self.lift_jeq();
        self.lift_jne();
    }

    fn apply(&mut self, mut t: VecDeque<(usize, LiftedOp)>, replace_size: usize, pass_name: &'static str) {
        self.replacements_per_pass.entry(pass_name).and_modify(|x| *x += t.len()).or_insert(t.len());

        let mut next_idx: usize = 0;
        self.instruction_stream = self.instruction_stream.iter().enumerate().filter_map(|(i, x)| {
            if let Some(new) = t.front() {
                if i >= new.0 && i < new.0 + (replace_size-1) {
                    return None;
                } else if i == new.0 + (replace_size-1) {
                    let val = Some(new.1.clone());
                    t.pop_front();
                    return val;
                }
            }
            Some(x.clone())
        }).collect::<Vec<_>>();
    }

    fn lift_mov(&mut self) {
        let mut movs: VecDeque<(usize, LiftedOp)> = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (LiftedOpcode::Unlifted(o1), LiftedOpcode::Unlifted(o2)) = (&window[0].opc, &window[1].opc) {
                match (o1.opc, o2.opc) {
                    (
                        Opcode::MemSub(memdst_1, src),
                        Opcode::MemSub(memdst_2, Operand::Mem(mem_src2))
                    ) if memdst_1 == mem_src2 && (memdst_1.addr == 0) => {
                        movs.push_back((i, LiftedOp { opc: LiftedOpcode::Add(LiftedOperand::from_operand(&Operand::Mem(memdst_2)), LiftedOperand::from_operand(&src)), pc: window[0].pc }));
                    },
                    _ => {}
                }
            }
        }
        self.apply(movs, 2, "lift_mov");
    }

    fn lift_zero(&mut self) {
        self.instruction_stream = self.instruction_stream.iter().enumerate().map(|(i, x)| {
            match x.opc {
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc, Operand::Mem(m)), .. })
                if m == memloc => {
                    LiftedOp { opc: LiftedOpcode::Zero(LiftedOperand::from_operand(&Operand::Mem(m))), pc: x.pc }
                },
                _ => x.clone()
            }

        }).collect::<Vec<_>>();
    }


    fn remove_bogus_jumps(&mut self) {
        self.instruction_stream.retain(|x| {
            if let LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(mem_loc, target), .. } ) = x.opc {
                target != x.pc as u64 + 3
            } else {
                true
            }
        });
    }

    // identify unconditional jumps
    fn jumps(&mut self) {
        let mut jmps: Vec<(usize, LiftedOp)> = Vec::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (LiftedOpcode::Unlifted(o1), LiftedOpcode::Unlifted(o2)) = (&window[0].opc, &window[1].opc) {
                match (o1.opc, o2.opc) {
                    (Opcode::MemSub(MemLoc { addr: 0 }, Operand::Mem(MemLoc { addr: 0 })), Opcode::JumpIfIndirectPositive(MemLoc { addr: 0 }, target)) => {
                        jmps.push((o1.pc, LiftedOp { opc: LiftedOpcode::Jmp(target), pc: window[0].pc }));
                    },
                    _ => {}
                }
            }
        }

        let mut next_idx: usize = 0;
        self.instruction_stream = self.instruction_stream.iter().filter_map(|x| {
            if next_idx < jmps.len() && jmps[next_idx].0 == x.pc {
                next_idx += 1;
                Some(jmps[next_idx-1].1.clone())
            } else if next_idx > 0 && jmps[next_idx-1].0 == x.pc {
                None
            } else {
                Some(x.clone())
            }
        }).collect::<Vec<_>>();
    }

    /*
    0x1517: ZERO R0
    0x151a: MemSub [0x0] -= [0x1] // 0x0 - 0x426 => 0xfffffffffffffbda
    0x151d: ZERO [0x1526]
    0x1520: MemSub [0x1526] -= [0x0] // 0x0 - 0xfffffffffffffbda => 0x426
    */
    fn lift_store(&mut self) {
        let mut stores: VecDeque<(usize, LiftedOp)> = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(4).enumerate() {
            if let (LiftedOpcode::Zero(o1), LiftedOpcode::Unlifted(o2), LiftedOpcode::Zero(o3), LiftedOpcode::Unlifted(o4)) = (&window[0].opc, &window[1].opc, &window[2].opc, &window[3].opc) {
                match (o2.opc, o4.opc) {
                    (
                        Opcode::MemSub(memdst_1, src),
                        Opcode::MemSub(memdst_2, Operand::Mem(mem_src2))
                    ) if memdst_1 == mem_src2 && (memdst_1.addr == 0) && *o1 == LiftedOperand::Reg(memdst_1.addr as u8) => {
                        stores.push_back((i, LiftedOp { opc: LiftedOpcode::Store(memdst_2, LiftedOperand::from_operand(&src)), pc: window[0].pc }));
                    },
                    _ => {}
                }
            }
        }
        self.apply(stores, 4, "lift_store");
    }

    /*
    0x1517: STORE [0x1526], R1
    0x1523: STORE [0x1534], [0x426]

    The 0x426 is overwritten
    */
    fn lift_store_indirect_1(&mut self) {
        let mut stores: VecDeque<(usize, LiftedOp)> = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (LiftedOpcode::Store(dst1, src1), LiftedOpcode::Store(dst2, src2)) = (&window[0].opc, &window[1].opc) {
                if dst1.addr as usize == window[1].pc + 3 {
                    assert!(matches!(src1, LiftedOperand::Reg(_)));
                    if let LiftedOperand::Reg(r1) = src1 {
                        stores.push_back((i, LiftedOp { opc: LiftedOpcode::Store(dst2.clone(), LiftedOperand::IndirectMem(*r1)), pc: window[0].pc }));
                    }
                }
            }
        }
        self.apply(stores, 2, "lift_store_indirect_1");
    }

    /* zero + add = mov */
    fn lift_zero_add(&mut self) {
        let mut movs: VecDeque<(usize, LiftedOp)> = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (
                LiftedOpcode::Zero(dst1),
                LiftedOpcode::Add(dst2, src2)
            ) = (&window[0].opc, &window[1].opc) {
                if dst1 == dst2{
                    movs.push_back((i, LiftedOp { opc: LiftedOpcode::Mov(dst2.clone(), src2.clone()), pc: window[0].pc }));
                }
            }
        }
        self.apply(movs, 2, "lift_zero_add");
    }

    /*
    0x13e0: ZERO R0
    0x13e3: ZERO [0x13fc]
    0x13e6: MOV [0x13fb], R1
    0x13ef: ZERO R0
    0x13f2: ADD [0x13fc], R1
    0x13f8: ZERO R0
    0x13fb: ZERO [0x600040c]
    0x13fe: MOV [0x140e], R1
    0x1407: ZERO R0
    0x140a: ADD [0x600040c], R3

    The 0x600040c is overwritten, this is an indirect store mov [rX], rY
    */
    fn lift_store_indirect_2(&mut self) {
        let mut stores: VecDeque<(usize, LiftedOp)> = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(10).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Zero(ins2_1),
                LiftedOpcode::Mov(ins1_1, target_addr1),
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Add(ins2_2, target_addr2),
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Mov(ins3_1, target_addr3),
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Add(_, src),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if [target_addr1, target_addr2, target_addr3].iter().all(|x| *x == target_addr1) {
                    if let LiftedOperand::Reg(r1) = target_addr1.clone() {
                        stores.push_back((i, LiftedOp { opc: LiftedOpcode::Mov(LiftedOperand::IndirectMem(r1), src.clone()), pc: window[0].pc }));
                    } else {
                        assert!(false, "expected reg");
                    }
                }
            }
        }
        self.apply(stores, 10, "lift_store_indirect_2");
    }

    /*
      0x165c: STORE [0x1679], [R1]
        0x1674: ZERO R1
        0x1677: JMP 0x42e
    */
    fn lift_indirect_jump(&mut self) {
        let mut jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(3).enumerate() {
            if let (
                LiftedOpcode::Store(MemLoc { addr: addr }, target),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Jmp(_),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if *addr as usize == window[0].pc + 0x1d {
                    jmps.push_back((i, LiftedOp { opc: LiftedOpcode::JmpIndirect(target.clone()), pc: window[0].pc }));
                }
            }
        }
        self.apply(jmps, 3, "lift_indirect_jump");
        jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(3).enumerate() {
            if let (
                LiftedOpcode::Store(MemLoc { addr: addr }, target),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Zero(_),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if *addr as usize == window[0].pc + 0x1d {
                    jmps.push_back((i, LiftedOp { opc: LiftedOpcode::JmpIndirect(target.clone()), pc: window[0].pc }));
                }
            }
        }
        self.apply(jmps, 3, "lift_indirect_jump");
    }

    /*
    indirect source

      0x1557: ZERO R0
  0x155a: ZERO R7
  0x155d: MemSub [0x0] -= [0x1] // 
  0x1560: ZERO [0x1569]
  0x1563: MemSub [0x1569] -= [0x0] // 
  0x1566: ADD R7, R16
    */
    fn lift_mov_mem_indirect(&mut self) {
        let mut jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(7).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Zero(dst_reg_1),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(MemLoc { addr: 0 }, src), .. }),
                LiftedOpcode::Zero(LiftedOperand::Mem(MemLoc { addr: instr_addr1 })),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(MemLoc { addr: instr_addr2 }, Operand::Mem(MemLoc { addr: 0 })), .. }),
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Add(dst_reg_2, _),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if *instr_addr1 as usize == window[0].pc + 0x12  && instr_addr1 == instr_addr2 && dst_reg_1 == dst_reg_2 {
                    if let LiftedOperand::Reg(r1) = LiftedOperand::from_operand(&src) {
                        jmps.push_back((i, LiftedOp { opc: LiftedOpcode::Mov(dst_reg_2.clone(), LiftedOperand::IndirectMem(r1)), pc: window[0].pc }));
                    } else {
                        panic!("expected reg");
                    }
                }
            }
        }
        self.apply(jmps, 7, "lift_mov_mem_indirect");
    }

    fn remove_redundant_zeroes(&mut self) {
        let mut replace = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Add(a, b),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                replace.push_back((i, LiftedOp { opc: LiftedOpcode::Add(a.clone(), b.clone()), pc: window[0].pc }));
            }
        }
        self.apply(replace, 2, "lift_zeroes_1");

        replace = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Mov(a, b),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                replace.push_back((i, LiftedOp { opc: LiftedOpcode::Mov(a.clone(), b.clone()), pc: window[0].pc }));
            }
        }
        self.apply(replace, 2, "lift_zeroes_2");

        replace = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(3).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Zero(LiftedOperand::Reg(1)),
                LiftedOpcode::Mov(a, b),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                replace.push_back((i, LiftedOp { opc: LiftedOpcode::Mov(a.clone(), b.clone()), pc: window[0].pc }));
            }
        }
        self.apply(replace, 3, "lift_zeroes_3");
        
        replace = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(3).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::Zero(LiftedOperand::Reg(1)),
                LiftedOpcode::Add(a, b),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                replace.push_back((i, LiftedOp { opc: LiftedOpcode::Add(a.clone(), b.clone()), pc: window[0].pc }));
            }
        }
        self.apply(replace, 3, "lift_zeroes_4");

        replace = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(0)),
                LiftedOpcode::BoundsCheck(a, b),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                replace.push_back((i, LiftedOp { opc: LiftedOpcode::BoundsCheck(a.clone(), b.clone()), pc: window[0].pc }));
            }
        }
        self.apply(replace, 2, "lift_zeroes_5");
    }

    /*
      0x516: ZERO R1
  0x519: MOV R9, [0x515]
  0x522: ZERO R0
  0x525: ADD R1, [0x515]
  0x52b: ZERO R0
  0x52e: ADD R1, R13
  0x534: JMP [R1]
  */
    fn lift_jumptable(&mut self) {
        let mut jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(7).enumerate() {
            if let (
                LiftedOpcode::Zero(LiftedOperand::Reg(r1_1)),
                LiftedOpcode::Mov(_, _),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Add(LiftedOperand::Reg(r1_2), LiftedOperand::Mem(MemLoc { addr: vtable_addr })),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Add(LiftedOperand::Reg(r1_3), r13_1),
                LiftedOpcode::JmpIndirect(LiftedOperand::IndirectMem(r1_4)),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if [r1_1, r1_2, r1_3, r1_4].iter().all(|x| *x == r1_1) {
                    jmps.push_back((i, LiftedOp { opc: LiftedOpcode::VtableJmp(*vtable_addr, r13_1.clone()), pc: window[0].pc }));
                }
            }
        }
        self.apply(jmps, 7, "lift_jumptable");
    }

    /*
  0x4a5: MemSub [0x8] -= [0xf] //  // mem[0xf] = 0xffffffffff000000
block_0x4a5:
  0x4a5: JumpIf [0x8] <= 0: 0x4a5 // 
block_0x4a8:
  0x4a8: MemSub [0x8] -= [0xe] //  // mem[0xe] = 0x1000000
  0x4ab: MemSub [0x8] -= [0x0] // 
  0x4ab: JumpIf [0x8] <= 0: 0x4b1 // 
block_0x4ae:
  0x4ae: JMP 0x4a8
  */
    fn lift_assert1(&mut self) {
        let mut jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(10).enumerate() {
            if let (
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_1, Operand::Mem(MemLoc { addr: 0xf })), .. }),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(memloc1_2, target1), .. }),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_3, Operand::Mem(MemLoc { addr: 0xe })), .. }),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_4, operand2_1), .. }),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(memloc1_5, target2), .. }),
                LiftedOpcode::Jmp(target3),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(operand2_2, Operand::Mem(memloc1_6)), .. }),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(memloc2_3, target4), .. }),
                LiftedOpcode::Zero(_),
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_7, Operand::Mem(MemLoc { addr: 0xf})), .. }),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if [memloc1_1, memloc1_2, memloc1_3, memloc1_4, memloc1_5, memloc1_6, memloc1_7].iter().all(|x| *x == memloc1_1) {
                    jmps.push_back((i, LiftedOp { opc: LiftedOpcode::BoundsCheck(LiftedOperand::from_operand(&Operand::Mem(*memloc1_1)), LiftedOperand::from_operand(operand2_1)), pc: window[0].pc }));
                }
            }
        }
        self.apply(jmps, 10, "lift_assert1");
    }


    /*
  0x7f3: MemSub [0x8] -= [0x7f2] //  // mem[0x7f2] = 0x1
  0x7f6: BOUNDS_CHECK R8 R0
  0x812: MOV R3, [0x811] // mem[0x811] = 0x6
  0x81b: ADD R1, R8
  0x824: ADD R1, R12
  0x82d: MOV [R1], R3
  */
    fn lift_push(&mut self) {
        let mut pushes = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(6).enumerate() {
            if let (
                LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(MemLoc { addr: 8 }, amount), .. }),
                LiftedOpcode::BoundsCheck(LiftedOperand::Reg(8), LiftedOperand::Reg(0)),
                LiftedOpcode::Mov(tmp_reg_1, val),
                LiftedOpcode::Add(LiftedOperand::Reg(addr_reg1), LiftedOperand::Reg(8)),
                LiftedOpcode::Add(LiftedOperand::Reg(addr_reg2), LiftedOperand::Reg(12)),
                LiftedOpcode::Mov(LiftedOperand::IndirectMem(addr_reg3), tmp_reg_2),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if addr_reg1 == addr_reg2 &&  addr_reg2 == addr_reg3 && tmp_reg_1 == tmp_reg_2 {
                    pushes.push_back((i, LiftedOp { opc: LiftedOpcode::Push(val.clone(), LiftedOperand::from_operand(amount)), pc: window[0].pc }));
                }
            }
        }
        self.apply(pushes, 6, "lift_push");
    }
    /*
      0x1247: ADD R1, R8
  0x1250: ADD R1, R12
  0x1259: MOV R4, [R1]
  0x1271: ADD R8, [0x127a] // mem[0x127a] = 0x1
  0x1281: BOUNDS_CHECK R8 R0
  */
    fn lift_pop(&mut self) {
        let mut pushes = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(5).enumerate() {
            if let (
                LiftedOpcode::Add(LiftedOperand::Reg(addr_reg1), LiftedOperand::Reg(8)),
                LiftedOpcode::Add(LiftedOperand::Reg(addr_reg2), LiftedOperand::Reg(12)),
                LiftedOpcode::Mov(tmp_reg_1, LiftedOperand::IndirectMem(addr_reg3)),
                LiftedOpcode::Add(LiftedOperand::Reg(8), amount),
                LiftedOpcode::BoundsCheck(LiftedOperand::Reg(8), LiftedOperand::Reg(0)),
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if addr_reg1 == addr_reg2 &&  addr_reg2 == addr_reg3 {
                    pushes.push_back((i, LiftedOp { opc: LiftedOpcode::Pop(tmp_reg_1.clone(), amount.clone()), pc: window[0].pc }));
                }
            }
        }
        self.apply(pushes, 5, "lift_pop");
    }

    fn remove_unnecessary_jumps(&mut self) {
        let mut jmps = VecDeque::new();
        for (i, window) in self.instruction_stream.windows(2).enumerate() {
            if let (
                LiftedOpcode::Jmp(target1),
                next_instr
            ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
                if *target1 as usize == window[1].pc {
                    jmps.push_back((i, LiftedOp { opc: next_instr.clone(), pc: window[0].pc }));
                }
            }
        }
        self.apply(jmps, 2, "remove_unnecessary_jumps");
    }

    /*
0x4bb0: MOV R3, R7
  0x4bbf: ADD R3, [0x4bc5] // mem[0x4bc5] = 0x2
  0x4bcc: BOUNDS_CHECK R3 R0
block_0x4be4:
  0x4be4: ADD R1, R3
  0x4bed: ADD R1, R12
  0x4bf6: MOV R3, [R1]
  */

  fn lift_peek(&mut self) {
    let mut pushes = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(6).enumerate() {
        if let (
            LiftedOpcode::Mov(tmp_reg_1_1, LiftedOperand::Reg(7)),
            LiftedOpcode::Add(tmp_reg_1_2, offset),
            LiftedOpcode::BoundsCheck(tmp_reg_1_3, LiftedOperand::Reg(0)),
            LiftedOpcode::Add(addr_reg_1_1, tmp_reg_1_4),
            LiftedOpcode::Add(addr_reg_1_2, LiftedOperand::Reg(12)),
            LiftedOpcode::Mov(destination, LiftedOperand::IndirectMem(addr_reg_1_3)),
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            if [tmp_reg_1_1, tmp_reg_1_2, tmp_reg_1_3, tmp_reg_1_4].iter().all(|x| *x == tmp_reg_1_1) 
            && addr_reg_1_1 == addr_reg_1_2 && *addr_reg_1_1 == LiftedOperand::Reg(*addr_reg_1_3) {
                pushes.push_back((i, LiftedOp { opc: LiftedOpcode::Peek(destination.clone(), offset.clone()), pc: window[0].pc }));
            }
        }
    }
    self.apply(pushes, 6, "lift_peek");
  }

  /*
  0x1b53: PEEK R3, [R7 + [0x1b68]]
  0x1bb1: ADD R3, [0x1bba] // mem[0x1bba] = 0x3
  0x1bc1: BOUNDS_CHECK R3 R0
block_0x1bd9:
  0x1bd9: ADD R1, R3
  0x1be2: ADD R1, R12
  0x1beb: MOV R3, [R1]
  */
  fn lift_buf_load(&mut self) {
    let mut pushes = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(6).enumerate() {
        if let (
            LiftedOpcode::Peek(tmp_reg_1_1, buf_local_idx),
            LiftedOpcode::Add(tmp_reg_1_2, index),
            LiftedOpcode::BoundsCheck(tmp_reg_1_3, LiftedOperand::Reg(0)),
            LiftedOpcode::Add(addr_reg_1_1, tmp_reg_1_4),
            LiftedOpcode::Add(addr_reg_1_2, LiftedOperand::Reg(12)),
            LiftedOpcode::Mov(destination, LiftedOperand::IndirectMem(addr_reg_1_3)),
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            if [tmp_reg_1_1, tmp_reg_1_2, tmp_reg_1_3, tmp_reg_1_4].iter().all(|x| *x == tmp_reg_1_1) 
            && addr_reg_1_1 == addr_reg_1_2 && *addr_reg_1_1 == LiftedOperand::Reg(*addr_reg_1_3) {
                pushes.push_back((i, LiftedOp { opc: LiftedOpcode::PeekBufLoad(destination.clone(), buf_local_idx.clone(), index.clone()), pc: window[0].pc }));
            }
        }
    }
    self.apply(pushes, 6, "lift_buf_load");
  }

  /*
    0x45de: PEEK R5, [R7 + [0x45f3]]
  0x463c: ADD R5, [0x4645] // mem[0x4645] = 0x5
  0x464c: BOUNDS_CHECK R5 R0
block_0x4664:
  0x4664: MOV R3, [0x466a] // mem[0x466a] = 0x0
  0x4674: ADD R1, R5
  0x467d: ADD R1, R12
  0x4686: MOV [R1], R3
  */
  fn lift_buf_store(&mut self) {
    let mut pushes = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(7).enumerate() {
        if let (
            LiftedOpcode::Peek(tmp_reg_1_1, buf_local_idx),
            LiftedOpcode::Add(tmp_reg_1_2, index),
            LiftedOpcode::BoundsCheck(tmp_reg_1_3, LiftedOperand::Reg(0)),
            LiftedOpcode::Mov(src_tmp_1, src),
            LiftedOpcode::Add(addr_reg_1_1, tmp_reg_1_4),
            LiftedOpcode::Add(addr_reg_1_2, LiftedOperand::Reg(12)),
            LiftedOpcode::Mov(LiftedOperand::IndirectMem(addr_reg_1_3), src_tmp_2),
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            if [tmp_reg_1_1, tmp_reg_1_2, tmp_reg_1_3, tmp_reg_1_4].iter().all(|x| *x == tmp_reg_1_1) 
            && addr_reg_1_1 == addr_reg_1_2 && *addr_reg_1_1 == LiftedOperand::Reg(*addr_reg_1_3)
            && src_tmp_1 == src_tmp_2 {
                pushes.push_back((i, LiftedOp { opc: LiftedOpcode::PeekBufStore(src.clone(), buf_local_idx.clone(), index.clone()), pc: window[0].pc }));
            }
        }
    }
    self.apply(pushes, 7, "lift_buf_store");
  }

  /*
    0x49e: PUSH [0x4c0] (shift=[0x4a1]) // val = 0x2, offs = 0x1
  0x50c: ZERO R0
  0x50f: ZERO R1
  0x512: VTABLEJMP table at [0x515], offset R13
  */
  fn lift_call(&mut self) {
    let mut calls = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(4).enumerate() {
        if let (
            LiftedOpcode::Push(src, _),
            LiftedOpcode::Zero(_),
            LiftedOpcode::Zero(_),
            LiftedOpcode::VtableJmp(table, _)
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            calls.push_back((i, LiftedOp { opc: LiftedOpcode::Call(table.clone(), src.clone()), pc: window[0].pc }));
        }
    }
    self.apply(calls, 4, "lift_call");
  }
/*
  0x109c: ZERO R0
  0x109f: MemSub [0x1] -= [0x1091] //  // mem[0x1091] = 0xa
  0x10a2: MemSub [0x1] -= [0x0] // 
  0x10a2: JumpIf [0x1] <= 0: 0x10a8 // 
block_0x10a5:
  0x10a5: JMP 0x10ea
block_0x10a8:
  0x10a8: MemSub [0x0] -= [0x1] // 
block_0x10a8:
  0x10a8: JumpIf [0x0] <= 0: 0x10ae // 
block_0x10ab:
  0x10ab: JMP 0x10ea
  */

  fn lift_jeq(&mut self) {
    let mut calls = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(8).enumerate() {
        if let (
            LiftedOpcode::Zero(LiftedOperand::Reg(0)),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_1, cmpop_1), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_2, Operand::Mem(MemLoc { addr: 0 })), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(memloc1_3, target1), .. }),
            LiftedOpcode::Jmp(out_target1),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(MemLoc { addr: 0 }, Operand::Mem(memloc1_4)), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(MemLoc { addr: 0 }, target2), .. }),
            LiftedOpcode::Jmp(out_target2)
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            if out_target1 == out_target2 && [memloc1_1, memloc1_2, memloc1_3, memloc1_4].iter().all(|x| *x == memloc1_1) {
                calls.push_back((i, LiftedOp { opc: LiftedOpcode::Jeq(LiftedOperand::Mem(*memloc1_1), LiftedOperand::from_operand(cmpop_1), *target2, out_target1.clone()), pc: window[0].pc }));
            }
        }
    }
    self.apply(calls, 8, "lift_jeq");
  }

  fn lift_jne(&mut self) {
    let mut calls = VecDeque::new();
    for (i, window) in self.instruction_stream.windows(8).enumerate() {
        if let (
            LiftedOpcode::Zero(LiftedOperand::Reg(0)),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_1, cmpop_1), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(memloc1_2, Operand::Mem(MemLoc { addr: 0 })), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(memloc1_3, tmp_target1), .. }),
            LiftedOpcode::Jmp(taken_target1),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::MemSub(MemLoc { addr: 0 }, Operand::Mem(memloc1_4)), .. }),
            LiftedOpcode::Unlifted(AnnotatedOpcode { opc: Opcode::JumpIfIndirectPositive(MemLoc { addr: 0 }, nottaken_target1), .. }),
            LiftedOpcode::Zero(LiftedOperand::Reg(0)),
        ) = window.iter().map(|x| &x.opc).next_tuple().unwrap() {
            if *tmp_target1 as usize == window[0].pc + 0xc && [memloc1_1, memloc1_2, memloc1_3, memloc1_4].iter().all(|x| *x == memloc1_1) {
                calls.push_back((i, LiftedOp { opc: LiftedOpcode::Jne(LiftedOperand::Mem(*memloc1_1), LiftedOperand::from_operand(cmpop_1), *taken_target1, *nottaken_target1), pc: window[0].pc }));
            }
        }
    }
    self.apply(calls, 8, "lift_jne");
  }


    /*

    stack:

    R8 is the stack pointer
    R7 is the frame pointer

    R8 -= 1
    [R12 + translate(R8)] = R7
    R7 = translate(R8)

    R8 = R7
    R7 = [R12 + R7]
    R8 += 1

    */

}