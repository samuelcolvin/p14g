//! Check untrusted SQL against an allowlist and rewrite it so it is safe to run on Postgres.
//!
//! pgsafe parses a statement, lowers it to a small representation of its own, checks every table,
//! column, operator and function against a [`Policy`], and writes the statement back out. Anything it
//! cannot represent is rejected. It never connects to a database.
//!
//! ```
//! use pgsafe::{Policy, Select};
//!
//! let policy: Policy = Policy::builder()
//!     .select(Select::table("orders").columns(["id", "product", "qty"]))
//!     .build()?;
//!
//! let safe = policy.check("select id from orders where qty < 3", &())?;
//! assert_eq!(safe.sql, r#"SELECT "orders"."id" FROM "orders" WHERE ("orders"."qty" < 3)"#);
//!
//! assert!(policy.check("select * from pg_shadow", &()).is_err());
//! # Ok::<(), pgsafe::Error>(())
//! ```
//!
//! pgsafe restricts tables, columns, operators and functions. It does not restrict rows: do that with a
//! view (ideally `security_barrier`, `WITH CHECK OPTION`) and list the view in the policy. It is one layer
//! of defence, to be used with a least-privilege database role and a `statement_timeout`.

pub mod ast;
mod backend;
mod check;
mod dialect;
mod error;
pub mod functions;
mod lower;
mod map;
mod policy;

pub use crate::{
    ast::StatementKind,
    backend::Backend,
    dialect::Dialect,
    error::{Error, ErrorKind, Location, Result},
    map::Mapper,
    policy::{Delete, Insert, Limits, Literals, Op, Policy, PolicyBuilder, SafeSql, Select, Star, Update},
};
