//! Parse untrusted SQL and lower sqlparser's AST into the p14g IR.
//!
//! Two rules keep this from quietly accepting syntax it does not understand:
//!
//! * every sqlparser struct is destructured with all of its fields named, never `..`, so a sqlparser
//!   upgrade that adds a field stops this compiling until someone decides what the new syntax means;
//! * nothing here formats a sqlparser node into the output. The only thing carried across is the value
//!   of identifiers and literals, which the writer escapes itself.
//!
//! A third rule is about not crashing: `Spanned::span` recurses over a whole subtree, and subtrees here
//! can be thousands of levels deep (see [`STACK_PER_TOKEN`]), so it is only ever called on names and
//! literals, which are flat.

mod dml;
mod expr;
mod query;

use sqlparser::{
    ast as sp,
    parser::{Parser, ParserError},
    tokenizer::{Span, Token, Tokenizer},
};

use crate::{
    ast::{Ident, Statement},
    dialect::Dialect,
    error::{Error, ErrorKind, Location, Result},
    policy::Limits,
};

pub(crate) struct Lowered {
    pub statement: Statement,
    /// The highest `$n` in the input, 0 when there are none.
    pub max_placeholder: u32,
}

/// Stack to have available per token of input, on top of [`STACK_BASE`].
///
/// sqlparser builds chains of infix and postfix operators (`1+1+1+...`, `x::int::int...`) with a loop, so
/// its recursion limit does not bound how deep they get: the tree can be half as deep as there are tokens.
/// Nothing in p14g recurses down such a tree further than `max_depth`, but dropping it does, and that
/// cannot be made iterative for a type from another crate. So the stack is sized for the worst case
/// instead. A debug build needs between 64 and 128 bytes a token for the deepest chains, so this leaves
/// a factor of eight; `deep_input_does_not_overflow` runs those chains on a thread with very little stack.
/// The stack is only allocated when the thread does not already have this much left, which for
/// statements of ordinary size it does.
const STACK_PER_TOKEN: usize = 1024;
const STACK_BASE: usize = 256 * 1024;

pub(crate) fn parse(sql: &str, dialect: Dialect, limits: &Limits) -> Result<Lowered> {
    if sql.len() > limits.max_sql_bytes {
        return Err(Error::limit(format!(
            "SQL is {} bytes, the limit is {}",
            sql.len(),
            limits.max_sql_bytes
        )));
    }
    let parser_dialect = dialect.parser_dialect();
    let tokens = Tokenizer::new(parser_dialect.as_ref(), sql)
        .tokenize_with_location()
        .map_err(|e| {
            Error::new(ErrorKind::Parse, e.message).at(location(Span {
                start: e.location,
                end: e.location,
            }))
        })?;
    // every node of the parsed statement takes at least one token, so this also bounds the tree
    let significant = tokens
        .iter()
        .filter(|token| !matches!(token.token, Token::Whitespace(_)))
        .count();
    if significant > limits.max_nodes {
        return Err(Error::limit(format!(
            "SQL has {significant} tokens, the limit is {}",
            limits.max_nodes
        )));
    }

    let stack = STACK_BASE + significant * STACK_PER_TOKEN;
    stacker::maybe_grow(stack, stack, || {
        let mut statements = Parser::new(parser_dialect.as_ref())
            .with_recursion_limit(limits.max_depth)
            .with_tokens_with_locations(tokens)
            .parse_statements()
            .map_err(|e| match e {
                ParserError::RecursionLimitExceeded => Error::limit("SQL is nested too deeply"),
                ParserError::TokenizerError(message) | ParserError::ParserError(message) => {
                    Error::new(ErrorKind::Parse, message)
                }
            })?;
        let statement = match (statements.pop(), statements.is_empty()) {
            (Some(statement), true) => statement,
            (None, _) => return Err(Error::new(ErrorKind::Parse, "no SQL statement found")),
            (Some(_), false) => {
                return Err(Error::new(
                    ErrorKind::Parse,
                    "expected exactly one SQL statement, found several",
                ));
            }
        };
        let mut lower = Lower {
            limits,
            nodes: 0,
            depth: 0,
            joins: 0,
            subqueries: 0,
            set_operations: 0,
            max_placeholder: 0,
        };
        let statement = lower.statement(statement)?;
        Ok(Lowered {
            statement,
            max_placeholder: lower.max_placeholder,
        })
    })
}

struct Lower<'a> {
    limits: &'a Limits,
    nodes: usize,
    depth: usize,
    joins: usize,
    subqueries: usize,
    set_operations: usize,
    max_placeholder: u32,
}

fn location(span: Span) -> Option<Location> {
    (span.start.line > 0).then_some(Location {
        line: span.start.line,
        column: span.start.column,
    })
}

/// Reject a clause that is present. `clause` is whatever `Option`, `Vec` or `bool` the parser filled in.
fn reject<T: Absent>(clause: &T, what: &str) -> Result<()> {
    if clause.is_absent() {
        Ok(())
    } else {
        Err(Error::unsupported(what))
    }
}

trait Absent {
    fn is_absent(&self) -> bool;
}

impl<T> Absent for Option<T> {
    fn is_absent(&self) -> bool {
        self.is_none()
    }
}

impl<T> Absent for Vec<T> {
    fn is_absent(&self) -> bool {
        self.is_empty()
    }
}

impl Absent for bool {
    fn is_absent(&self) -> bool {
        !*self
    }
}

impl Lower<'_> {
    fn statement(&mut self, statement: sp::Statement) -> Result<Statement> {
        match statement {
            sp::Statement::Query(query) => Ok(Statement::Query(self.query(*query)?)),
            sp::Statement::Insert(insert) => Ok(Statement::Insert(self.insert(insert)?)),
            sp::Statement::Update(update) => Ok(Statement::Update(self.update(update)?)),
            sp::Statement::Delete(delete) => Ok(Statement::Delete(self.delete(delete)?)),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                "only SELECT, INSERT, UPDATE and DELETE statements are supported",
            )),
        }
    }

    /// Count one node against the limit.
    fn node(&mut self) -> Result<()> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            Err(Error::limit(format!(
                "SQL has more than {} nodes",
                self.limits.max_nodes
            )))
        } else {
            Ok(())
        }
    }

    /// Run `f` one level deeper, failing if that is too deep.
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.depth >= self.limits.max_depth {
            return Err(Error::limit("SQL is nested too deeply"));
        }
        self.depth += 1;
        let result = f(self);
        self.depth -= 1;
        result
    }

    fn count_subquery(&mut self) -> Result<()> {
        self.subqueries += 1;
        if self.subqueries > self.limits.max_subqueries {
            Err(Error::limit(format!(
                "SQL has more than {} subqueries",
                self.limits.max_subqueries
            )))
        } else {
            Ok(())
        }
    }
}

/// Lower an identifier to the name Postgres would resolve it to.
///
/// Unquoted names are folded to lower case the way Postgres does it (ASCII only). If Postgres would fold
/// differently that is harmless: the folded name is what gets checked against the policy and it is also
/// what gets written, quoted, so the database cannot see a different name from the one that was checked.
fn ident(ident: sp::Ident) -> Result<Ident> {
    let sp::Ident {
        value,
        quote_style,
        span,
    } = ident;
    let value = match quote_style {
        None => value.to_ascii_lowercase(),
        Some('"' | '`') => value,
        Some(other) => {
            return Err(Error::unsupported(format!("identifier quoted with {other}")).at(location(span)));
        }
    };
    Ident::new(value).map_err(|e| e.at(location(span)))
}

/// Where a name starts. Not `Spanned::span`, which would walk the arguments of a function-style name part.
fn name_location(name: &sp::ObjectName) -> Option<Location> {
    match name.0.first() {
        Some(sp::ObjectNamePart::Identifier(first)) => location(first.span),
        _ => None,
    }
}

/// Lower a possibly qualified name of at most `max_parts` parts.
fn object_name(name: sp::ObjectName, what: &str, max_parts: usize) -> Result<Vec<Ident>> {
    let at = name_location(&name);
    let sp::ObjectName(parts) = name;
    if parts.is_empty() || parts.len() > max_parts {
        return Err(Error::unsupported(format!("{what} with {} name parts", parts.len())).at(at));
    }
    parts
        .into_iter()
        .map(|part| match part {
            sp::ObjectNamePart::Identifier(i) => ident(i),
            sp::ObjectNamePart::Function(_) => Err(Error::unsupported(format!("a function call in {what}")).at(at)),
        })
        .collect()
}

/// Lower a name that must be a single identifier.
fn single_name(name: sp::ObjectName, what: &str) -> Result<Ident> {
    let mut parts = object_name(name, what, 1)?;
    Ok(parts.remove(0))
}

/// Lower `name` or `schema.name`.
fn qualified_name(name: sp::ObjectName, what: &str) -> Result<(Option<Ident>, Ident)> {
    let mut parts = object_name(name, what, 2)?;
    let name = parts.pop().expect("object_name returns at least one part");
    Ok((parts.pop(), name))
}
