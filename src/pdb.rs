use std::env::current_exe;
use std::path::Path;
use std::process::{Command, ExitStatus};

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX: Regex =
        Regex::new(r"(?m)^.*?PROC.*?\[.*?:(?P<offset>[0-9a-fA-F]*?)\], Cb: (?P<length>[0-9a-fA-F]*?),.*?, (?P<name>.*?)\r?$")
            .unwrap();
}

// pdb symbol offset + offset_compare = file offset
// this is 0x1000 for VC6 linked files, 0x400 for VC5 linked files
pub const PDB_OFFSET_COMPARE_FILE: u64 = 0x1000;
pub const PDB_SEGMENT_OFFSET: u64 = 0x0040_1000;

#[derive(Debug)]
pub enum PdbError {
    IoError(std::io::Error),
    CvDumpUnsuccessful(CvDumpError),
    Utf8Error(std::string::FromUtf8Error),
}

#[derive(Debug)]
pub struct CvDumpError {
    pub error_code: i32,
    pub stdout: String,
}

#[derive(Debug)]
pub struct FunctionSymbol<'a> {
    pub name: &'a str,
    pub offset: u64,
    pub size: usize,
}

#[derive(Debug)]
pub struct Pdb {
    stdout: String,
    status: ExitStatus,
}

impl Pdb {
    pub fn new(file: impl AsRef<Path>) -> Result<Self, PdbError> {
        let mut cvdump_exe_path = current_exe().map_err(PdbError::IoError)?;
        cvdump_exe_path.set_file_name("cvdump.exe");

        let cvdump = (if cfg!(target_os = "windows") {
            Command::new(cvdump_exe_path)
        } else {
            let mut c = Command::new("wine");
            c.arg(cvdump_exe_path);
            c
        }).arg("-s")
        .arg(file.as_ref())
        .output()
        .map_err(PdbError::IoError)?;

        let stdout = String::from_utf8(cvdump.stdout).map_err(PdbError::Utf8Error)?;

        if !cvdump.status.success() {
            return Err(PdbError::CvDumpUnsuccessful(CvDumpError {
                error_code: cvdump.status.code().unwrap_or(0),
                stdout,
            }));
        }

        Ok(Pdb {
            stdout,
            status: cvdump.status,
        })
    }

    pub fn parse_pdb(&self) -> impl Iterator<Item = FunctionSymbol> {
        REGEX
            .captures_iter(&self.stdout)
            .map(|caps| FunctionSymbol {
                name: caps.name("name").unwrap().into(),
                offset: u64::from_str_radix(&caps["offset"], 16).unwrap(),
                size: usize::from_str_radix(&caps["length"], 16).unwrap(),
            })
    }
}
