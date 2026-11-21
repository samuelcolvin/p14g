//! Postgres spellings.

use std::fmt::Write;

use super::Syntax;
use crate::{
    ast::{DataType, Ident},
    functions,
};

pub(super) struct Postgres;

impl Syntax for Postgres {
    /// Always double-quoted, with `"` doubled. [`Ident`] has already ruled out NUL and names long enough
    /// for Postgres to truncate.
    fn ident(&self, out: &mut String, ident: &Ident) {
        out.push('"');
        for c in ident.as_str().chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
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

    /// Builtins are qualified with `pg_catalog`, so that a function of the same name earlier in the
    /// `search_path` cannot stand in for them.
    fn function_name(&self, out: &mut String, schema: Option<&Ident>, name: &Ident) {
        match schema {
            Some(schema) => {
                self.ident(out, schema);
                out.push('.');
            }
            None if functions::is_default(name.as_str()) => out.push_str("pg_catalog."),
            None => {}
        }
        self.ident(out, name);
    }
}
