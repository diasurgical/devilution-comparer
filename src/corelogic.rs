use std::any::Any;
use std::env::current_exe;
use std::ffi::CStr;

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::raw::c_char;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use regex::Regex;
use zydis::gen::*;
use zydis::*;

use self::CoreError::*;
use super::hexformat::*;

// pdb symbol offset + offset_compare = file offset
// this is 0x1000 for VC6 linked files, 0x400 for VC5 linked files
const OFFSET_COMPARE_FILE: u64 = 0x1000;

#[derive(Debug)]
pub struct Opts {
    pub file_opts: FileOpts,
    pub display_opts: DisplayOpts,
    pub last_offset_length: Option<(u64, usize)>,
    pub enable_watcher: bool,
}

#[derive(Debug, Clone)]
pub struct DisplayOpts {
    pub print_adresses: bool,
    pub show_mem_disp: bool,
    pub show_imms: bool,
}

#[derive(Debug)]
pub struct FileOpts {
    pub orig: PathBuf,
    pub compare_file_path: PathBuf,
    pub compare_pdb_file: PathBuf,
    pub debug_symbol: String,
    pub orig_offset_start: u64,
}

pub enum CoreError {
    CvDumpFail(std::io::Error),
    CvDumpUnsuccessful,
    SymbolNotFound,
    IoError(std::io::Error),
    ZydisError(ZydisStatusCode),
}

pub fn run_compare(mut opts: &mut Opts) -> Result<(u64, usize), CoreError> {
    let cvdump_exe_path = current_exe().map_err(IoError)?.with_file_name("cvdump.exe");

    let cvdump = (if cfg!(target_os = "windows") {
        Command::new(cvdump_exe_path)
    } else {
        let mut c = Command::new("wine");
        c.arg(cvdump_exe_path);
        c
    }).arg("-s")
    .arg(&opts.file_opts.compare_pdb_file)
    .output()
    .map_err(CvDumpFail)?;

    if !cvdump.status.success() {
        //println!("Could not read the pdb file, skipping the file.");
        return Err(CvDumpUnsuccessful);
    }

    let cvdump_output = String::from_utf8_lossy(&cvdump.stdout);

    let regex =
        Regex::new(r"\[[\da-fA-F]*?:(?P<offset>[\da-fA-F]*)\], Cb: (?P<length>[\da-fA-F]*)")
            .unwrap();

    let symbol_info = cvdump_output
        .lines()
        .find(|line| line.ends_with(&opts.file_opts.debug_symbol) && line.contains("PROC"))
        .map(|line| {
            let captures = regex.captures(line).unwrap();
            let offset = u64::from_str_radix(&captures["offset"], 16).unwrap();
            let length = usize::from_str_radix(&captures["length"], 16).unwrap();
            (offset, length)
        });

    let (offset, length) = match symbol_info {
        None => {
            return Err(SymbolNotFound);
        }
        Some(info) => info,
    };

    let mut orig_function_bytes = Vec::with_capacity(length);
    orig_function_bytes.extend((0..length).map(|_| 0));
    let mut compare_function_bytes = Vec::with_capacity(length);
    compare_function_bytes.extend((0..length).map(|_| 0));

    read_file_into(
        &mut orig_function_bytes,
        &opts.file_opts.orig,
        opts.file_opts.orig_offset_start,
    )?;
    read_file_into(
        &mut compare_function_bytes,
        &opts.file_opts.compare_file_path,
        offset + OFFSET_COMPARE_FILE,
    )?;

    let mut formatter = Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL).map_err(ZydisError)?;
    formatter
        .set_print_address(Box::new(format_addrs))
        .map_err(ZydisError)?;

    if !opts.display_opts.show_mem_disp {
        formatter
            .set_print_displacement(Box::new(void_format_disp))
            .map_err(ZydisError)?;
    }

    if !opts.display_opts.show_imms {
        formatter
            .set_print_immediate(Box::new(void_format_imms))
            .map_err(ZydisError)?;
    }

    let decoder =
        Decoder::new(ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32).map_err(ZydisError)?;

    let curdir = std::env::current_dir().map_err(IoError)?;

    let orig_offset = opts.file_opts.orig_offset_start;
    write_disasm(
        "orig.asm",
        &curdir,
        &orig_function_bytes,
        &formatter,
        &decoder,
        &mut opts,
        orig_offset,
    )?;

    write_disasm(
        "compare.asm",
        &curdir,
        &compare_function_bytes,
        &formatter,
        &decoder,
        &mut opts,
        offset,
    )?;

    Ok((offset, length))
}

fn read_file_into(buffer: &mut [u8], path: impl AsRef<Path>, offset: u64) -> Result<(), CoreError> {
    File::open(path)
        .and_then(|mut f| f.seek(SeekFrom::Start(offset)).map(|_| f))
        .and_then(|mut f| f.read_exact(buffer))
        .map_err(IoError)
}

fn write_disasm(
    filename: impl AsRef<Path>,
    curdir: &PathBuf,
    bytes: &[u8],
    formatter: &Formatter,
    decoder: &Decoder,
    opts: &mut Opts,
    offset: u64,
) -> Result<(), CoreError> {
    let mut buf = [0u8; 255];
    let mut path = curdir.clone();
    path.push(filename);
    File::create(path).map_err(IoError).and_then(|file| {
        let mut buf_writer = BufWriter::new(file);

        for (insn, ip) in decoder.instruction_iterator(bytes, offset) {
            formatter
                .format_instruction_raw(&insn, &mut buf, Some(&mut opts.display_opts))
                .map_err(ZydisError)?;

            let insn_str =
                unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }.to_string_lossy();

            if opts.display_opts.print_adresses {
                writeln!(buf_writer, "{:X}: {}", ip, insn_str);
            } else {
                writeln!(buf_writer, "{}", insn_str);
            }
        }

        Ok(())
    })?;

    Ok(())
}

fn format_addrs(
    _: &Formatter,
    buf: &mut Buffer,
    insn: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: u64,
    display_opts: Option<&mut Any>,
) -> ZydisResult<()> {
    let opts = display_opts.unwrap().downcast_ref::<DisplayOpts>().unwrap();
    match op.type_ {
        // memory address
        2 => {
            if opts.show_mem_disp {
                if insn.opcode == 0xFF && [2, 3].contains(&insn.raw.modrm.reg) {
                    buf.append("<indir_fn>")? // hide function call addresses, 0xFF /3 = CALL m16:32)
                } else {
                    buf.append(&format!("{:#X}", op.mem.disp.value))?
                }
            } else {
                buf.append("<indir_addr>")?
            }
        }
        // immediate address
        4 => match insn.opcode {
            0xE8 => buf.append("<imm_fn>")?, // hide function call addresses, 0xE8 = CALL rel32
            _ => {
                if op.imm.isRelative != 0 {
                    buf.append("$")?;
                } else {
                    buf.append("<imm_addr>")?;
                    return Ok(());
                }
                if op.imm.isSigned != 0 {
                    buf.append(&format!(
                        "{:+#X}",
                        CustomUpperHexFormat(*unsafe { op.imm.value.s.as_ref() })
                    ))?;
                } else {
                    buf.append(&format!("{:+#X}", unsafe { op.imm.value.u.as_ref() }))?;
                }
            }
        },
        _ => {}
    }

    Ok(())
}

fn void_format_disp(
    _: &Formatter,
    buf: &mut Buffer,
    _: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: Option<&mut Any>,
) -> ZydisResult<()> {
    buf.append(if op.mem.disp.value < 0 { "-" } else { "+" })?;
    buf.append(&format!("<disp{}>", op.elementSize))?;
    Ok(())
}

fn void_format_imms(
    _: &Formatter,
    buf: &mut Buffer,
    _: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: Option<&mut Any>,
) -> ZydisResult<()> {
    buf.append(&format!("<imm{}>", op.elementSize))?;
    Ok(())
}
