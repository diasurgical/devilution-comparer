use std::env::current_exe;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use capstone::prelude::*;
use regex::Regex;

// pdb symbol offset + offset_compare = file offset
// this is 0x1000 for VC6 linked files, 0x400 for VC5 linked files
const OFFSET_COMPARE_FILE: u64 = 0x1000;

pub struct Opts {
    pub orig: PathBuf,
    pub compare_file_path: PathBuf,
    pub compare_pdb_file: PathBuf,
    pub orig_offset_start: u64,
    pub debug_symbol: String,
    pub print_adresses: bool,
    pub last_offset_length: Option<(u64, usize)>,
    pub enable_watcher: bool,
}

pub enum CoreError {
    CvDumpFail(std::io::Error),
    CvDumpUnsuccessful,
    SymbolNotFound,
    IoError(std::io::Error),
    CapstoneError(capstone::Error),
}

pub fn run_compare(opts: &Opts) -> Result<(u64, usize), CoreError> {
    let cvdump_exe_path = current_exe()
        .map_err(CoreError::IoError)?
        .with_file_name("cvdump.exe");

    let cvdump = (if cfg!(target_os = "windows") {
        Command::new(cvdump_exe_path)
    } else {
        let mut c = Command::new("wine");
        c.arg(cvdump_exe_path);
        c
    }).arg("-s")
    .arg(&opts.compare_pdb_file)
    .output()
    .map_err(CoreError::CvDumpFail)?;

    if !cvdump.status.success() {
        //println!("Could not read the pdb file, skipping the file.");
        return Err(CoreError::CvDumpUnsuccessful);
    }

    let cvdump_output = String::from_utf8_lossy(&cvdump.stdout);

    let regex =
        Regex::new(r"\[[\da-fA-F]*?:(?P<offset>[\da-fA-F]*)\], Cb: (?P<length>[\da-fA-F]*)")
            .unwrap();

    let symbol_info = cvdump_output
        .lines()
        .find(|line| line.ends_with(&opts.debug_symbol) && line.contains("PROC"))
        .map(|line| {
            let captures = regex.captures(line).unwrap();
            let offset = u64::from_str_radix(&captures["offset"], 16).unwrap();
            let length = usize::from_str_radix(&captures["length"], 16).unwrap();
            (offset, length)
        });

    let (offset, length) = match symbol_info {
        None => {
            return Err(CoreError::SymbolNotFound);
        }
        Some(info) => info,
    };

    let mut orig_function_bytes = Vec::with_capacity(length);
    orig_function_bytes.extend((0..length).map(|_| 0));
    let mut compare_function_bytes = Vec::with_capacity(length);
    compare_function_bytes.extend((0..length).map(|_| 0));

    read_file_into(&mut orig_function_bytes, &opts.orig, opts.orig_offset_start)?;
    read_file_into(
        &mut compare_function_bytes,
        &opts.compare_file_path,
        offset + OFFSET_COMPARE_FILE,
    )?;

    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .map_err(CoreError::CapstoneError)?;

    let curdir = std::env::current_dir().map_err(CoreError::IoError)?;

    write_disasm(
        "orig.asm",
        &curdir,
        &orig_function_bytes,
        &mut cs,
        &opts,
        offset,
    )?;

    write_disasm(
        "compare.asm",
        &curdir,
        &compare_function_bytes,
        &mut cs,
        &opts,
        offset,
    )?;

    Ok((offset, length))
}

fn read_file_into(buffer: &mut [u8], path: impl AsRef<Path>, offset: u64) -> Result<(), CoreError> {
    File::open(path)
        .and_then(|mut f| {
            f.seek(SeekFrom::Start(offset))
                .map(|_| f)
        }).and_then(|mut f| f.read_exact(buffer))
        .map_err(CoreError::IoError)
}

fn write_disasm(
    filename: impl AsRef<Path>,
    curdir: &PathBuf,
    bytes: &[u8],
    cs: &mut Capstone,
    opts: &Opts,
    offset: u64,
) -> Result<(), CoreError> {
    cs.disasm_all(&bytes, offset + OFFSET_COMPARE_FILE)
        .map_err(CoreError::CapstoneError)
        .and_then(|insns| {
            let mut path = curdir.clone();
            path.push(filename);
            File::create(path)
                .map_err(CoreError::IoError)
                .map(|file| (insns, file))
        }).map(|(insns, file)| {
            let mut buf = BufWriter::new(file);

            for i in insns.iter() {
                if opts.print_adresses {
                    writeln!(buf, "{}", i);
                } else {
                    writeln!(
                        buf,
                        "{} {}",
                        i.mnemonic().unwrap_or(""),
                        i.op_str().unwrap_or("")
                    );
                }
            }
        })
}
