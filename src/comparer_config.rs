use std::path::Path;

use serde_derive::Deserialize;

const COMPARER_CONFIG_FILE: &str = "comparer-config.toml";

#[derive(Debug, Deserialize)]
pub struct ComparerConfig {
    pub address_offset: u64,
    pub func: Vec<FunctionDefinition>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub addr: u64,
    pub size: Option<usize>,
}

#[derive(Debug)]
pub enum ComparerConfigError {
    IoError(std::io::Error),
    ParseError(toml::de::Error),
}

impl ComparerConfig {
    fn read_from_file(path: impl AsRef<Path>) -> Result<Self, ComparerConfigError> {
        Ok(toml::from_str::<Self>(
            &std::fs::read_to_string(path).map_err(ComparerConfigError::IoError)?,
        ).map_err(ComparerConfigError::ParseError)?)
    }

    pub fn read_default() -> Result<Self, ComparerConfigError> {
        let mut path = std::env::current_exe().map_err(ComparerConfigError::IoError)?;
        path.set_file_name(COMPARER_CONFIG_FILE);
        Self::read_from_file(path)
    }
}
