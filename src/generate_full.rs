use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::iter::FromIterator;
use std::path::PathBuf;

use self::GenerateFullCommandError::*;
use super::comparer_config::*;
use super::disasm::*;
use super::pdb::*;

#[derive(Debug)]
pub struct GenerateFullCommandInfo {
    pub file_path: PathBuf,
    pub orig_file: bool,
    pub disasm_opts: super::DisasmOpts,
}

#[derive(Debug)]
pub enum GenerateFullCommandError {
    PdbError(super::pdb::PdbError),
    IoError(std::io::Error),
    DisasmError(super::disasm::DisasmError),
    FunctionDefSizeWrong(String),
}

pub fn run(
    info: GenerateFullCommandInfo,
    cfg: &ComparerConfig,
) -> Result<(), GenerateFullCommandError> {
    if info.orig_file {
        generate_full_orig(info, cfg)
    } else {
        generate_full_pdb(info, cfg)
    }
}

fn generate_full_orig(
    mut info: GenerateFullCommandInfo,
    cfg: &ComparerConfig,
) -> Result<(), GenerateFullCommandError> {
    let mut path = std::env::current_dir().map_err(IoError)?;
    path.push("orig_full.asm");

    let bytes = std::fs::read(&info.file_path).map_err(IoError)?;

    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    File::create(path)
        .map_err(IoError)
        .map(BufWriter::new)
        .and_then(|mut writer| {
            for func in &cfg.func {
                let size = match func.size {
                    None => {
                        writeln!(
                            stdout_lock,
                            "Note: Skipping '{}' because no size was defined.",
                            func.name
                        ).map_err(IoError)?;
                        continue;
                    }
                    Some(size) => size,
                };

                write_function_head(&mut writer, size, func.name.as_ref())?;

                let offset = (func.addr - cfg.address_offset) as usize;
                let offset_end = offset + size;

                let func_bytes = bytes
                    .get(offset..offset_end)
                    .ok_or_else(|| FunctionDefSizeWrong(func.name.clone()))?;

                write_disasm(&mut writer, func_bytes, &mut info.disasm_opts, func.addr)
                    .map_err(DisasmError)?;
            }
            Ok(())
        })?;

    Ok(())
}

fn generate_full_pdb(
    mut info: GenerateFullCommandInfo,
    cfg: &ComparerConfig,
) -> Result<(), GenerateFullCommandError> {
    let mut pdb_path = info.file_path.clone();
    pdb_path.set_extension("pdb");

    let pdb = Pdb::new(pdb_path).map_err(PdbError)?;
    let mut pdb_funcs: HashMap<&str, FunctionSymbol> =
        HashMap::from_iter(pdb.parse_pdb().map(|func| (func.name, func)));

    let mut path = std::env::current_dir().map_err(IoError)?;
    path.push("compare_full.asm");

    let bytes = std::fs::read(&info.file_path).map_err(IoError)?;

    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    File::create(path)
        .map_err(IoError)
        .map(BufWriter::new)
        .and_then(|mut writer| {
            for func in &cfg.func {
                if let Some(pdb_func) = pdb_funcs.remove::<str>(func.name.as_ref()) {
                    write_function_head(&mut writer, pdb_func.size, func.name.as_ref())?;

                    let offset = (pdb_func.offset + PDB_OFFSET_COMPARE_FILE) as usize;
                    let offset_end = offset + pdb_func.size;

                    let func_bytes = bytes
                        .get(offset..offset_end)
                        .ok_or_else(|| FunctionDefSizeWrong(func.name.clone()))?;

                    write_disasm(
                        &mut writer,
                        func_bytes,
                        &mut info.disasm_opts,
                        pdb_func.offset + PDB_SEGMENT_OFFSET,
                    ).map_err(DisasmError)?;
                } else {
                    writeln!(
                        stdout_lock,
                        "WARN: Function '{}' was not found in the PDB.",
                        func.name
                    ).map_err(IoError)?;
                }
            }
            for func in pdb_funcs {
                writeln!(
                    stdout_lock,
                    "WARN: Function '{}' was not found in the config.",
                    func.1.name
                ).map_err(IoError)?;
            }
            Ok(())
        })?;

    Ok(())
}

fn write_function_head(
    writer: &mut impl Write,
    size: usize,
    name: &str,
) -> Result<(), GenerateFullCommandError> {
    // (blank line)
    // ;
    // ; <function>
    // ; size: 0xDEADBEEF
    // ;
    // (blank line)
    writeln!(writer, "\n;\n; {}\n; size: {:#X}\n;\n", name, size).map_err(IoError)
}

pub fn print_error(e: &GenerateFullCommandError) {
    match e {
        PdbError(e) => println!("PDB file error: {:#?}", e),
        IoError(e) => println!("IO error: {:#?}", e),
        DisasmError(e) => println!("Zydis disassembly engine error: {:#?}", e),
        FunctionDefSizeWrong(s) => println!(
            "Error: The function offset/size of {} are outside of \
             the bounds of the input file.",
            s
        ),
    }
}
