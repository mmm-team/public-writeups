use std::fmt;
use std::io::{BufReader, BufRead};
use std::fs::File;

use crate::lifter::check_opaque_jump;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Operand {
    Mem(MemLoc),
    Read // bignum or char
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct MemLoc {
    pub addr: u64,
}

impl MemLoc {
    pub fn get_reg(&self) -> Option<u8> {
        if self.addr < 0x100 {
            Some(self.addr as u8)
        } else {
            None
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Opcode {
    MemSub(MemLoc, Operand),
    Print(Operand),
    JumpIfIndirectPositive(MemLoc, u64)
}

impl fmt::Debug for MemLoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:#x}]", self.addr)
    }
}
impl fmt::Debug for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Mem(x) => x.fmt(f),
            Operand::Read => write!(f, "input()")
        }
    }
}
impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opcode::MemSub(memloc, val) => {
                write!(f, "MemSub {:?} -= {:?}", memloc, val)
            },
            Opcode::Print(operand) => {
                write!(f, "Print {:?}", operand)
            },
            Opcode::JumpIfIndirectPositive(memloc, target) => {
                write!(f, "JumpIf {:?} <= 0: {:#x}", memloc, target)
            }
        }
    }
}

fn is_negative(x: u64) -> bool{
    (x >> 63) != 0
}

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

pub struct Disassembler<'a> {
    pub mem: &'a mut Vec<u64>,
    pub pc: usize,
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct AnnotatedOpcode {
    pub opc: Opcode,
    pub annotation: String,
    pub pc: usize,
}
impl fmt::Debug for AnnotatedOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} // {}", self.opc, self.annotation)
    }
}

impl<'a> Disassembler<'a> {
    // single basic block
    pub fn disassemble_and_propagate(&mut self) -> (Vec<AnnotatedOpcode>, Vec<usize>) {
        let mut annotated = vec![];
        let mut successors = vec![];
        loop {
            if (self.pc > self.mem.len()) {
                break;
            }
            let ops = disass(self.mem, self.pc);

            // Annotate + Look for successors
            annotated.extend(ops.iter().map(|o| {
                let annotation = match o {
                    Opcode::MemSub(memloc, operand) => {
                        let mut annotation = "".to_string();
                        if let Operand::Mem(MemLoc { addr }) = operand {
                            if let (Some(src_val), Some(dst_val)) = (self.mem.get(*addr as usize), self.mem.get(memloc.addr as usize)) {
                                let result = dst_val.wrapping_sub(*src_val);
                                annotation = format!("{:#x} - {:#x} => {:#x}", dst_val, src_val, result);
                                self.mem[memloc.addr as usize] = result;
                            }
                        }
                        annotation
                    },
                    Opcode::JumpIfIndirectPositive(memloc, target) => {
                        let mut annotation = "".to_string();
                        if (self.pc + 3) == *target as usize {
                            annotation = format!("(fall through always)");
                            // successors.push(self.pc + 3);
                        } else if check_opaque_jump(&ops) {
                            annotation = format!("(jump always)");
                            successors.push(*target as usize);
                        } else if let Some(val) = self.mem.get(memloc.addr as usize) {
                            if (self.pc + 3 > 0x100) {
                                successors.push(self.pc + 3);
                            }
                            if (*target as usize) > 0x100 {
                                successors.push(*target as usize);
                            }
                            if *val as i64 > 0 {
                                annotation = format!("jump not taken");
                            } else {
                                annotation = format!("jump taken");
                            }
                        }
                        annotation
                    },
                    _ => "".to_string()
                };
                AnnotatedOpcode { opc: *o, annotation: "".to_string(), pc: self.pc }

            }));

            if successors.len() != 0 {
                break;
            } else {
                self.pc += 3;
            }
        }
        return (annotated, successors)
    }
}
