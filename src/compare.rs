use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;

use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};

use self::CompareError::*;
use super::comparer_config::*;
use super::disasm::*;
use super::pdb::*;
use super::CustomUpperHexFormat;

#[derive(Debug)]
pub struct CompareCommandInfo {
    pub compare_opts: CompareOpts,
    pub disasm_opts: super::DisasmOpts,
    pub last_offset_size: Option<(u64, usize)>,
    pub enable_watcher: bool,
    pub truncate_to_original: bool,
}

#[derive(Debug)]
pub struct CompareOpts {
    pub orig: PathBuf,
    pub compare_file_path: PathBuf,
    pub compare_pdb_file: PathBuf,
    pub debug_symbol: String,
}

#[derive(Debug)]
pub enum CompareError {
    PdbError(super::pdb::PdbError),
    ConfigSymbolNotFound,
    SymbolNotFound,
    IoError(std::io::Error),
    DisasmError(super::disasm::DisasmError),
    NotifyError(notify::Error),
    RequiredFunctionSizeNotFoundError(String),
}

pub fn print_error(e: &CompareError) {
    match e {
        PdbError(e) => println!("PDB file error: {:#?}", e),
        ConfigSymbolNotFound => println!("Could not find the specified symbol in the config."),
        SymbolNotFound => println!("Could not find the symbol in the PDB, skipping the file."),
        IoError(e) => println!("IO error: {:#?}", e),
        DisasmError(e) => println!("Zydis disassembly engine error: {:#?}", e),
        NotifyError(e) => println!("Watcher error: {:#?}", e),
        RequiredFunctionSizeNotFoundError(e) => println!(
            "No size defined for the original function '{}', but truncate_to_original was specified.",
            e
        ),
    }
}

pub fn run(mut info: CompareCommandInfo, cfg: &ComparerConfig) -> Result<(), CompareError> {
    let orig_fn = cfg
        .func
        .iter()
        .find(|s| s.name == info.compare_opts.debug_symbol)
        .ok_or(ConfigSymbolNotFound)?;

    if orig_fn.size == None {
        if info.truncate_to_original {
            return Err(RequiredFunctionSizeNotFoundError(orig_fn.name.clone()));
        } else {
            println!(
                "WARN: No size defined for the original function, using the PDB function size instead."
            );
        }
    }

    // initial run
    run_disassemble(&mut info, cfg.address_offset, orig_fn)?;

    if !info.enable_watcher {
        return Ok(());
    }

    let (tx, rx) = channel();

    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, Duration::from_secs(2)).map_err(NotifyError)?;

    watcher
        .watch(
            &info.compare_opts.compare_pdb_file,
            RecursiveMode::NonRecursive,
        )
        .map_err(NotifyError)?;

    println!(
        "Started watching {} for changes. CTRL+C to quit.",
        info.compare_opts.compare_pdb_file.to_string_lossy()
    );

    loop {
        match rx.recv() {
            Ok(DebouncedEvent::Create(_)) | Ok(DebouncedEvent::Write(_)) => {
                if let Err(e) = run_disassemble(&mut info, cfg.address_offset, orig_fn) {
                    print_error(&e);
                }
            }
            Err(e) => {
                println!("Watcher error: {:#?}", e);
                std::process::exit(1);
            }
            _ => {}
        }
    }
}

fn run_disassemble(
    info: &mut CompareCommandInfo,
    orig_addr_offset: u64,
    orig_fn: &FunctionDefinition,
) -> Result<(), CompareError> {
    match write_compare(info, orig_addr_offset, orig_fn) {
        Ok((addr, size)) => {
            if let Some((old_addr, old_size)) = info.last_offset_size {
                print!(
                    "Found {} at {:#X} ({:+#X}), size: {:#X} ({:+#X})",
                    &info.compare_opts.debug_symbol,
                    addr,
                    CustomUpperHexFormat((addr as i64) - (old_addr as i64)),
                    size,
                    CustomUpperHexFormat((size as i64) - (old_size as i64)),
                );
            } else {
                print!(
                    "Found {} at {:#X}, size: {:#X}",
                    &info.compare_opts.debug_symbol, addr, size,
                );
            }

            if let Some(orig_size) = orig_fn.size {
                println!("; orig size: {:#X}", orig_size);
            } else {
                println!();
            }

            info.last_offset_size = Some((addr, size));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn write_compare(
    info: &mut CompareCommandInfo,
    orig_addr_offset: u64,
    orig_fn: &FunctionDefinition,
) -> Result<(u64, usize), CompareError> {
    let pdb = Pdb::new(&info.compare_opts.compare_pdb_file).map_err(PdbError)?;
    let FunctionSymbol { offset, size, .. } = pdb
        .parse_pdb()
        .find(|symbol| symbol.name == info.compare_opts.debug_symbol)
        .ok_or(SymbolNotFound)?;

    let mut orig_function_bytes = if let Some(orig_size) = orig_fn.size {
        vec![0; orig_size]
    } else {
        vec![0; size]
    };

    let mut compare_function_bytes = if info.truncate_to_original {
        vec![0; orig_fn.size.expect("orig size is None even though truncate_to_original is set. Initial check was wrong!")]
    } else {
        vec![0; size]
    };

    let orig_offset = orig_fn.addr - orig_addr_offset;

    read_file_into(
        &mut orig_function_bytes,
        &info.compare_opts.orig,
        orig_offset,
    )?;
    read_file_into(
        &mut compare_function_bytes,
        &info.compare_opts.compare_file_path,
        offset + PDB_OFFSET_COMPARE_FILE,
    )?;

    let curdir = std::env::current_dir().map_err(IoError)?;

    let mut path = curdir.clone();
    path.push("orig.asm");
    File::create(path)
        .map(BufWriter::new)
        .map_err(IoError)
        .and_then(|mut buf_writer| {
            write_disasm(
                &mut buf_writer,
                &orig_function_bytes,
                &mut info.disasm_opts,
                orig_fn.addr,
            )
            .map_err(DisasmError)?;

            Ok(())
        })?;

    let addr = offset + PDB_SEGMENT_OFFSET;

    let mut path = curdir;
    path.push("compare.asm");
    File::create(path)
        .map(BufWriter::new)
        .map_err(IoError)
        .and_then(|mut buf_writer| {
            write_disasm(
                &mut buf_writer,
                &compare_function_bytes,
                &mut info.disasm_opts,
                addr,
            )
            .map_err(DisasmError)?;

            Ok(())
        })?;

    Ok((addr, size))
}

fn read_file_into(
    buffer: &mut [u8],
    path: impl AsRef<Path>,
    offset: u64,
) -> Result<(), CompareError> {
    File::open(path)
        .and_then(|mut f| f.seek(SeekFrom::Start(offset)).map(|_| f))
        .and_then(|mut f| f.read_exact(buffer))
        .map_err(IoError)
}
