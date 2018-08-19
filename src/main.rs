use clap::{App, Arg};
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

mod corelogic;
use self::corelogic::write_decompiled;

fn main() {
    let cmdline = App::new("devilution-comparer")
        .about("Generates orig.txt and compare.txt in the current working directory.")
        .arg(
            Arg::with_name("ORIG_FILE")
                .help("Path to the original file to use")
                .required(true)
                .validator_os(file_exists),
        ).arg(
            Arg::with_name("ORIG_OFFSET_START")
                .help("Offset into the original file, decimal or hex number (0xDEADBEEF)")
                .required(true)
                .validator(is_vaild_number),
        ).arg(
            Arg::with_name("COMPARE_FILE")
                .help(
                    "Sets the debug binary file to use. \
                     The respective .pdb file needs to exist as well. \
                     Currently VC6 generated files only.",
                ).required(true)
                .validator_os(file_and_pdb_exists),
        ).arg(
            Arg::with_name("DEBUG_SYMBOL")
                .help(
                    "Function name/debug symbol to compare. This also defines the length \
                     of code in the original file to compare to.",
                ).required(true),
        ).get_matches();

    let orig = cmdline.value_of_os("ORIG_FILE").unwrap();
    let compare_file = cmdline.value_of_os("COMPARE_FILE").unwrap();
    let orig_offset_start = cmdline
        .value_of("ORIG_OFFSET_START")
        .map(|s| parse_offset(s).unwrap())
        .unwrap();
    let debug_symbol = cmdline.value_of("DEBUG_SYMBOL").unwrap();

    if let Err(e) = watch(orig, orig_offset_start, compare_file, debug_symbol) {
        println!("error: {:?}", e)
    }
}

fn watch(
    orig: impl AsRef<Path>,
    orig_offset_start: u64,
    compare_file: impl AsRef<Path>,
    debug_symbol: &str,
) -> notify::Result<()> {
    let pdb: &Path = &compare_file.as_ref().with_extension("pdb");

    // initial run
    write_decompiled(
        orig.as_ref(),
        orig_offset_start,
        compare_file.as_ref(),
        pdb,
        debug_symbol,
    ).unwrap();

    let (tx, rx) = channel();

    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2))?;

    watcher.watch(pdb, RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
            Ok(DebouncedEvent::Create(_)) | Ok(DebouncedEvent::Write(_)) => {
                println!("PDB change detected. Updating...");
                write_decompiled(
                    orig.as_ref(),
                    orig_offset_start,
                    compare_file.as_ref(),
                    pdb,
                    debug_symbol,
                ).unwrap();
            }
            Err(e) => println!("watch error: {:?}", e),
            _ => {}
        }
    }
}

fn is_vaild_number(v: String) -> Result<(), String> {
    parse_offset(&v)
        .map(|_| ())
        .map_err(|_| "Argument has to be a decimal or hex (0xDEADBEEF) number".to_owned())
}

fn parse_offset(v: &str) -> Result<u64, std::num::ParseIntError> {
    if v.starts_with("0x") {
        u64::from_str_radix(&v[2..], 16)
    } else {
        u64::from_str_radix(&v, 10)
    }
}

fn file_exists(v: &OsStr) -> Result<(), OsString> {
    if Path::new(v).exists() {
        Ok(())
    } else {
        let mut err = OsString::from("File not found: ");
        err.push(v);
        Err(err)
    }
}

fn file_and_pdb_exists(v: &OsStr) -> Result<(), OsString> {
    file_exists(v).and_then(|_| file_exists(Path::new(v).with_extension("pdb").as_os_str()))
}
