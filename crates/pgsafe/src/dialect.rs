//! The SQL dialect the untrusted input is written in.

use sqlparser::dialect as sp;

use crate::error::{Error, Result};

/// Dialect used to parse the input. The output is always written for the configured backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Dialect {
    #[default]
    Postgres,
    Generic,
    Ansi,
    MySql,
    Sqlite,
}

impl Dialect {
    pub fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "generic" => Ok(Self::Generic),
            "ansi" => Ok(Self::Ansi),
            "mysql" => Ok(Self::MySql),
            "sqlite" => Ok(Self::Sqlite),
            _ => Err(Error::config(format!("unknown dialect {name:?}"))),
        }
    }

    pub(crate) fn parser_dialect(self) -> Box<dyn sp::Dialect> {
        match self {
            Self::Postgres => Box::new(sp::PostgreSqlDialect {}),
            Self::Generic => Box::new(sp::GenericDialect {}),
            Self::Ansi => Box::new(sp::AnsiDialect {}),
            Self::MySql => Box::new(sp::MySqlDialect {}),
            Self::Sqlite => Box::new(sp::SQLiteDialect {}),
        }
    }
}
