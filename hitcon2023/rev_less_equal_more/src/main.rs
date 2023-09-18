
use std::fmt;
use std::io::{BufReader, BufRead};
use std::fs::File;
use std::collections::{HashMap, HashSet, VecDeque};

mod disass;
use disass::*;

mod lifter;
use lifter::{Lifter, LiftedOpcode};

fn main() {
    let file = File::open("../chal.txt").expect("file wasn't found.");
    let reader = BufReader::new(file);

    let mut mem: Vec<u64> = reader
        .lines()
        .filter_map(|line| {
            line.map(|x| x.split(" ").filter_map(|x| x.parse::<i64>().map(|y| y as u64).ok()).collect::<Vec<u64>>()).ok()
        })
        .flatten()
        .collect();
    
    let mut d = Disassembler { mem: &mut mem, pc: 0 };

    let mut blocks: HashMap<usize, Vec<AnnotatedOpcode>> = HashMap::new();
    let mut worklist = VecDeque::new();
    worklist.push_back(0);

    let mut stats: HashMap<&'static str, usize> = HashMap::new();
    let mut funcs: HashSet<usize> = HashSet::new();

    let mut count = 0;
    while worklist.len() > 0 {
        d.pc = worklist.pop_front().unwrap();
        if blocks.contains_key(&d.pc) {
            continue;
        }
        let orig_pc = d.pc;
        let (anno_ops, mut succs) = d.disassemble_and_propagate();

        blocks.entry(orig_pc).or_insert(anno_ops.clone());

        let mut l = Lifter::new(&anno_ops, &mut stats);
        l.lift();
        for a in l.instruction_stream {
            match a.opc {
                LiftedOpcode::VtableJmp(table_addr, _) => {
                    succs.append(&mut a.opc.vtable_targets(&d.mem, true, true));
                    funcs.extend(a.opc.vtable_targets(&d.mem, false, false).iter());
                },
                _ => {}
            }
        }
        

        for s in succs {
            worklist.push_back(s);
        }
        count += 1;
    }

    let mut ordered_blocks = blocks.keys().cloned().collect::<Vec<usize>>();
    ordered_blocks.sort();

    let mut seen_insns: HashSet<usize> = HashSet::new();
    let mut complete_instruction_stream = vec![];
    for start_pc in ordered_blocks {
        if seen_insns.contains(&start_pc) {
            continue;
        }
        let v = blocks.get(&start_pc).unwrap();
        let mut l = Lifter::new(&v, &mut stats);
        l.lift();
        for a in l.instruction_stream {
            seen_insns.insert(a.pc);
            complete_instruction_stream.push(a);
        }
    }

    // cross-block lifts
    let mut l = Lifter::new_for_cross_block_lifts(complete_instruction_stream, &mut stats);
    l.cross_block_lifts();

    for insn in l.instruction_stream {
        if funcs.contains(&insn.pc) {
            println!("");
            println!("func_{:#x}:", insn.pc);
        } else if blocks.contains_key(&insn.pc) {
            println!("block_{:#x}:", insn.pc);
        }
        print!("  {:?}", insn);
        if let Some(s) = insn.opc.comment(&d.mem) {
            print!("{}", s);
        }
        println!("");
        if matches!(insn.opc, LiftedOpcode::VtableJmp(_, _) | LiftedOpcode::Call(_, _)) {
            for target in insn.opc.vtable_targets(&d.mem, false, true) {
                println!("  - target block_{:#x}", target);
            }
        }
    }

    for (pass, count) in stats.iter() {
        println!("{}: {} replacements", pass, count);
    }
}