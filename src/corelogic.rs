use std::env::current_exe;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

use capstone::prelude::*;
use regex::Regex;

// pdb symbol offset + offset_compare = file offset
const OFFSET_COMPARE_FILE: u64 = 0x1000;

pub fn write_decompiled(
    orig: impl AsRef<Path>,
    orig_offset_start: u64,
    compare_file_path: impl AsRef<Path>,
    compare_pdb_file: impl AsRef<Path>,
    debug_symbol: &str,
) -> std::io::Result<()> {
    let cvdump_exe_path = current_exe()?.with_file_name("cvdump.exe");

    let cvdump = Command::new(cvdump_exe_path)
        .arg("-s")
        .arg(compare_pdb_file.as_ref())
        .output()?;

    if !cvdump.status.success() {
        println!("Could not read pdb, aborting.");
        return Ok(());
    }

    let cvdump_output = String::from_utf8_lossy(&cvdump.stdout);

    let regex =
        Regex::new(r"\[[\da-fA-F]*?:(?P<offset>[\da-fA-F]*)\], Cb: (?P<length>[\da-fA-F]*)")
            .unwrap();

    let symbol_info = cvdump_output
        .lines()
        .find(|line| line.ends_with("InitMonsterTRN") && line.contains("PROC"))
        .map(|line| {
            let captures = regex.captures(line).unwrap();
            let offset = u64::from_str_radix(&captures["offset"], 16).unwrap();
            let length = usize::from_str_radix(&captures["length"], 16).unwrap();
            (offset, length)
        });

    let (offset, length) = match symbol_info {
        None => {
            println!("Could not find the symbol, skipping.");
            return Ok(());
        }
        Some(info) => info,
    };

    println!(
        "found {} at offset: {:X}, length: {:X}",
        debug_symbol, offset, length
    );

    let mut orig_function_bytes = Vec::with_capacity(length);
    orig_function_bytes.extend((0..length).map(|_| 0));
    let mut compare_function_bytes = Vec::with_capacity(length);
    compare_function_bytes.extend((0..length).map(|_| 0));

    {
        let mut orig_file = File::open(orig.as_ref())?;
        orig_file.seek(SeekFrom::Start(orig_offset_start))?;
        orig_file.read_exact(orig_function_bytes.as_mut_slice())?;
    }
    {
        let mut compare_file = File::open(compare_file_path.as_ref())?;
        compare_file.seek(SeekFrom::Start(offset + OFFSET_COMPARE_FILE))?;
        compare_file.read_exact(compare_function_bytes.as_mut_slice())?;
    }

    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .unwrap();

    {
        let instructions = cs
            .disasm_all(&orig_function_bytes, offset + OFFSET_COMPARE_FILE)
            .unwrap();
        let mut output_file = std::env::current_dir()?;
        output_file.push("orig.asm");
        let out = File::create(output_file)?;
        let mut buf = BufWriter::new(out);
        for i in instructions.iter() {
            writeln!(buf, "{}", i);
        }
    }
    {
        let instructions = cs
            .disasm_all(&compare_function_bytes, offset + OFFSET_COMPARE_FILE)
            .unwrap();
        let mut output_file = std::env::current_dir()?;
        output_file.push("compare.asm");
        let out = File::create(output_file)?;
        let mut buf = BufWriter::new(out);
        for i in instructions.iter() {
            writeln!(buf, "{}", i);
        }
    }

    Ok(())
}
