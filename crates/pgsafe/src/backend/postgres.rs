//! Postgres spellings.

use std::fmt::Write;

use super::{QuoteIdentifiers, Syntax, keywords};
use crate::{
    ast::{DataType, Ident},
    functions,
};

pub(super) struct Postgres {
    pub quote: QuoteIdentifiers,
    pub qualify_builtins: bool,
}

/// Whether `name` is lower case letters, digits and underscores, not starting with a digit: the names
/// Postgres does not change when it reads them unquoted.
fn plain_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Postgres {
    fn quoted(out: &mut String, name: &str) {
        out.push('"');
        for c in name.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    }
}

impl Syntax for Postgres {
    /// Double-quoted, with `"` doubled, unless the policy asks for minimal quoting and the name is plain
    /// and not a keyword. [`Ident`] has already ruled out NUL and names long enough for Postgres to truncate.
    fn ident(&self, out: &mut String, ident: &Ident) {
        let name = ident.as_str();
        if self.quote == QuoteIdentifiers::Minimal && plain_name(name) && !keywords::is_keyword(name) {
            out.push_str(name);
        } else {
            Self::quoted(out, name);
        }
    }

    /// After a `.` Postgres's grammar takes any word as a name, keywords included (`t.user`, `t.select`),
    /// so only the spelling decides.
    fn member(&self, out: &mut String, ident: &Ident) {
        let name = ident.as_str();
        if self.quote == QuoteIdentifiers::Minimal && plain_name(name) {
            out.push_str(name);
        } else {
            Self::quoted(out, name);
        }
    }

    /// A value with no backslash is written `'...'` with quotes doubled, which reads the same whatever
    /// `standard_conforming_strings` is set to. A value with a backslash is written `E'...'` with the
    /// backslashes doubled, because that form also means the same under either setting.
    fn string(&self, out: &mut String, value: &str) {
        let escape = value.contains('\\');
        if escape {
            out.push('E');
        }
        out.push('\'');
        for c in value.chars() {
            match c {
                '\'' => out.push_str("''"),
                '\\' if escape => out.push_str("\\\\"),
                c => out.push(c),
            }
        }
        out.push('\'');
    }

    fn placeholder(&self, out: &mut String, number: u32) {
        write!(out, "${number}").expect("writing to a String cannot fail");
    }

    fn data_type(&self, out: &mut String, data_type: DataType) {
        let name = match data_type {
            DataType::SmallInt => "smallint",
            DataType::Integer => "integer",
            DataType::BigInt => "bigint",
            DataType::Numeric(None) => "numeric",
            DataType::Numeric(Some((precision, scale))) => {
                write!(out, "numeric({precision}").expect("writing to a String cannot fail");
                if let Some(scale) = scale {
                    write!(out, ", {scale}").expect("writing to a String cannot fail");
                }
                ")"
            }
            DataType::Real => "real",
            DataType::DoublePrecision => "double precision",
            DataType::Text => "text",
            DataType::Varchar(None) => "varchar",
            DataType::Varchar(Some(length)) => {
                write!(out, "varchar({length}").expect("writing to a String cannot fail");
                ")"
            }
            DataType::Boolean => "boolean",
            DataType::Date => "date",
            DataType::Time => "time",
            DataType::Timestamp => "timestamp",
            DataType::TimestampTz => "timestamp with time zone",
            DataType::Interval => "interval",
            DataType::Uuid => "uuid",
            DataType::Json => "json",
            DataType::Jsonb => "jsonb",
            DataType::Bytea => "bytea",
        };
        out.push_str(name);
    }

    /// With `qualify_builtins`, the default functions are written `pg_catalog.name`, so that a function of
    /// the same name in another schema of the `search_path` cannot be picked instead. Postgres prefers the
    /// function whose argument types match exactly, wherever it is in the path.
    fn function_name(&self, out: &mut String, schema: Option<&Ident>, name: &Ident) {
        match schema {
            Some(schema) => {
                self.ident(out, schema);
                out.push('.');
                self.member(out, name);
            }
            None if self.qualify_builtins && functions::is_default(name.as_str()) => {
                out.push_str("pg_catalog.");
                self.member(out, name);
            }
            None => {
                let name = name.as_str();
                let bare = plain_name(name) && (!keywords::is_keyword(name) || keywords::keyword_function_name(name));
                if self.quote == QuoteIdentifiers::Minimal && bare {
                    out.push_str(name);
                } else {
                    Self::quoted(out, name);
                }
            }
        }
    }
}
