//! Check untrusted SQL against an allowlist and rewrite it so it is safe to run on Postgres.
//!
//! p14g parses a statement, lowers it to a small representation of its own, checks every table,
//! column, operator and function against a [`Policy`], and writes the statement back out. Anything it
//! cannot represent is rejected. It never connects to a database.
//!
//! ```
//! use p14g::{Policy, Select};
//!
//! let policy: Policy = Policy::builder()
//!     .select(Select::table("orders").columns(["id", "product", "qty"]))
//!     .build()?;
//!
//! let safe = policy.rewrite("select id from orders where qty < 3", &())?;
//! assert_eq!(safe.sql, "SELECT orders.id\nFROM orders\nWHERE orders.qty < 3");
//!
//! assert!(policy.rewrite("select * from pg_shadow", &()).is_err());
//! # Ok::<(), p14g::Error>(())
//! ```
//!
//! p14g restricts tables, columns, operators and functions, and rows through a rule's `filter`. A filter
//! does not stop errors or timing from telling the author something about the rows it excludes; row-level
//! security or a `security_barrier` view does. p14g is one layer of defence, to be used with a
//! least-privilege database role and a `statement_timeout`.

pub mod ast;
mod backend;
mod check;
mod dialect;
mod error;
mod filter;
pub mod functions;
mod lower;
mod map;
mod policy;

pub use crate::{
    ast::StatementKind,
    backend::{Backend, Layout, QuoteIdentifiers},
    dialect::Dialect,
    error::{Error, ErrorKind, Location, Result},
    map::Mapper,
    policy::{
        Delete, Filter, FilterValue, Insert, Limits, Literals, Op, Policy, PolicyBuilder, SafeSql, Select, Star, Update,
    },
};
