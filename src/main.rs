mod cmdline;
mod compare;
mod comparer_config;
mod disasm;
mod generate_full;
mod hexformat;
mod pdb;

pub use self::compare::{CompareCommandInfo, CompareOpts};
use self::comparer_config::ComparerConfig;
pub use self::disasm::{DisasmError, DisasmOpts};
pub use self::generate_full::GenerateFullCommandInfo;
pub use self::hexformat::CustomUpperHexFormat;

pub enum Command {
    Compare(CompareCommandInfo),
    GenerateFull(GenerateFullCommandInfo),
}

fn main() {
    let command = cmdline::parse_cmdline();
    let comparer_config = match ComparerConfig::read_default() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!("Error reading the config file: {:#?}", e);
            std::process::exit(1);
        }
    };

    match command {
        Command::Compare(info) => {
            if let Err(e) = compare::run(info, &comparer_config) {
                compare::print_error(&e);
                std::process::exit(1);
            }
        }
        Command::GenerateFull(info) => {
            if let Err(e) = generate_full::run(info, &comparer_config) {
                generate_full::print_error(&e);
                std::process::exit(1);
            }
        }
    }
}
